document.addEventListener('DOMContentLoaded', () => {
    let decryptedAccounts = [];
    let encryptionKey = null;
    let vaultSalt = null;
    let totpGenerator;

    const appWrapper = document.getElementById('app-wrapper');
    const authModal = document.getElementById('auth-modal');
    const authModalContent = authModal.querySelector('.modal-content');
    const accountsContainer = document.getElementById('accounts-container');
    const progressBar = document.querySelector('.progress-bar');
    const fab = document.getElementById('fab');
    const fabMenu = document.getElementById('fab-menu');
    const addAccountModal = document.getElementById('add-account-modal');
    const actionModal = document.getElementById('action-modal');
    const confirmModal = document.getElementById('confirm-modal');
    const toastContainer = document.getElementById('toast-container');
    const importFileInput = document.getElementById('import-file-input');

    const cryptoHelpers = {
        deriveKey: async (password, salt) => {
            const enc = new TextEncoder();
            const keyMaterial = await window.crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
            return window.crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 200000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        },
        encrypt: async (data, key) => {
            const enc = new TextEncoder();
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedData = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(JSON.stringify(data)));
            return { iv: Array.from(iv), data: Array.from(new Uint8Array(encryptedData)) };
        },
        decrypt: async (encryptedData, iv, key) => {
            const dec = new TextDecoder();
            const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, new Uint8Array(encryptedData));
            return JSON.parse(dec.decode(decrypted));
        }
    };

    const UIRenderer = {
        showSetup: () => {
            authModalContent.innerHTML = `<h2>Create Vault</h2><p>Set a master password to encrypt your accounts.</p><div class="error-message"></div><input type="password" id="setup-password" placeholder="Master Password"><input type="password" id="setup-confirm" placeholder="Confirm Password"><div class="modal-actions"><button id="create-vault-btn" class="btn-primary">Create Vault</button></div>`;
            document.getElementById('create-vault-btn').addEventListener('click', handleCreateVault);
        },
        showLogin: () => {
            authModalContent.innerHTML = `<h2>Unlock Vault</h2><p>Enter your master password.</p><div class="error-message"></div><input type="password" id="login-password" placeholder="Master Password" autocomplete="current-password"><div class="modal-actions"><button id="unlock-btn" class="btn-primary">Unlock</button></div>`;
            document.getElementById('unlock-btn').addEventListener('click', handleUnlock);
            document.getElementById('login-password').focus();
        },
        showMainApp: () => {
            authModal.classList.add('hidden');
            appWrapper.classList.remove('hidden');
            renderAccounts();
            if (!totpGenerator) {
                totpGenerator = setInterval(updateCodes, 1000);
            }
        },
        showError: (message) => {
            const errorEl = authModalContent.querySelector('.error-message');
            if (errorEl) errorEl.textContent = message;
        }
    };

    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast-message';
        toast.textContent = message;
        toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }

    function showConfirmModal(title, message) {
        return new Promise((resolve) => {
            confirmModal.querySelector('#confirm-title').textContent = title;
            confirmModal.querySelector('#confirm-message').textContent = message;
            confirmModal.classList.remove('hidden');

            const handleConfirm = () => {
                confirmModal.classList.add('hidden');
                resolve(true);
            };
            const handleCancel = () => {
                confirmModal.classList.add('hidden');
                resolve(false);
            };

            confirmModal.querySelector('[data-action="confirm"]').addEventListener('click', handleConfirm, { once: true });
            confirmModal.querySelector('[data-action="cancel"]').addEventListener('click', handleCancel, { once: true });
        });
    }

    async function saveVault() {
        if (!encryptionKey || !vaultSalt) return;
        const { iv, data } = await cryptoHelpers.encrypt(decryptedAccounts, encryptionKey);
        const vaultPayload = { salt: Array.from(vaultSalt), iv, data };
        await fetch('/api/vault', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(vaultPayload) });
    }

    async function handleCreateVault() {
        const password = document.getElementById('setup-password').value;
        const confirm = document.getElementById('setup-confirm').value;
        if (password.length < 8) return UIRenderer.showError('Password must be at least 8 characters.');
        if (password !== confirm) return UIRenderer.showError('Passwords do not match.');
        vaultSalt = window.crypto.getRandomValues(new Uint8Array(16));
        encryptionKey = await cryptoHelpers.deriveKey(password, vaultSalt);
        decryptedAccounts = [];
        await saveVault();
        UIRenderer.showMainApp();
    }

    async function handleUnlock() {
        const password = document.getElementById('login-password').value;
        if (!password) return;
        try {
            const response = await fetch('/api/vault');
            const vault = await response.json();
            vaultSalt = new Uint8Array(vault.salt);
            const key = await cryptoHelpers.deriveKey(password, vaultSalt);
            const accounts = await cryptoHelpers.decrypt(vault.data, vault.iv, key);
            encryptionKey = key;
            decryptedAccounts = accounts;
            UIRenderer.showMainApp();
        } catch (error) {
            UIRenderer.showError('Incorrect password or corrupted vault.');
        }
    }

    function renderAccounts() {
        if (decryptedAccounts.length === 0) {
            accountsContainer.innerHTML = `<p>No accounts found. Use the '+' button to add some.</p>`;
            return;
        }
        accountsContainer.innerHTML = '';
        decryptedAccounts.forEach(acc => {
            const card = document.createElement('div');
            card.className = 'account-card';
            card.dataset.id = acc.id;
            card.innerHTML = `<div class="account-info"><span class="issuer">${acc.issuer}</span><span class="code" data-secret="${acc.secret}">000 000</span></div><div class="actions"><button class="copy-btn" title="Copy code"><i class="far fa-copy"></i></button><button class="kebab-btn" title="More options"><i class="fas fa-ellipsis-v"></i></button></div>`;

            const codeEl = card.querySelector('.code');
            const copyBtn = card.querySelector('.copy-btn');
            const kebabBtn = card.querySelector('.kebab-btn');

            const copyAction = async () => {
                const rawToken = codeEl.textContent.replace(/\s/g, '');
                if (rawToken && rawToken !== '000000' && rawToken !== 'Error') {
                    await copyToClipboard(rawToken, copyBtn);
                }
            };

            copyBtn.addEventListener('click', copyAction);
            codeEl.addEventListener('dblclick', copyAction);
            kebabBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                openActionModal(acc.id);
            });

            accountsContainer.appendChild(card);
        });
        updateCodes();
    }

    function openActionModal(accountId) {
        const account = decryptedAccounts.find(acc => acc.id === accountId);
        if (!account) return;
        actionModal.dataset.id = accountId;
        actionModal.querySelector('#edit-issuer').value = account.issuer;
        actionModal.classList.remove('hidden');
    }

    async function copyToClipboard(text, feedbackElement) {
        try {
            await navigator.clipboard.writeText(text);
            if (feedbackElement) {
                const originalIcon = feedbackElement.innerHTML;
                feedbackElement.innerHTML = '<i class="fas fa-check"></i>';
                feedbackElement.classList.add('copied');
                setTimeout(() => {
                    feedbackElement.innerHTML = originalIcon;
                    feedbackElement.classList.remove('copied');
                }, 1500);
            } else {
                showToast('Copied to clipboard!');
            }
        } catch (err) {
            console.error('Failed to copy: ', err);
        }
    }

    function updateCodes() {
        const epoch = Math.floor(Date.now() / 1000);
        const timeStep = 30;
        const counter = Math.floor(epoch / timeStep);
        const seconds = timeStep - (epoch % timeStep);
        progressBar.style.width = `${(seconds / timeStep) * 100}%`;

        document.querySelectorAll('.code').forEach(async (codeEl) => {
            const secret = codeEl.dataset.secret;
            const token = await generateToken(secret, counter);
            codeEl.textContent = `${token.slice(0, 3)} ${token.slice(3, 6)}`;
        });
    }

    async function generateToken(secret, counter) {
        try {
            const key = await window.crypto.subtle.importKey('raw', base32toBuf(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
            const mac = await window.crypto.subtle.sign('HMAC', key, to64BitBigEndian(counter));
            const macBytes = new Uint8Array(mac);
            const offset = macBytes[macBytes.length - 1] & 0x0f;
            const code = ((macBytes[offset] & 0x7f) << 24 | (macBytes[offset + 1] & 0xff) << 16 | (macBytes[offset + 2] & 0xff) << 8 | (macBytes[offset + 3] & 0xff)) % 1000000;
            return code.toString().padStart(6, '0');
        } catch (e) { return "Error"; }
    }

    function base32toBuf(base32) {
        const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let bits = "";
        let a = [];
        for (let i = 0; i < base32.length; i++) {
            const val = base32chars.indexOf(base32.charAt(i).toUpperCase());
            if (val < 0) continue;
            bits += val.toString(2).padStart(5, '0');
        }
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            a.push(parseInt(bits.substr(i, 8), 2));
        }
        return new Uint8Array(a);
    }

    function to64BitBigEndian(num) {
        const b = new ArrayBuffer(8);
        const v = new DataView(b);
        v.setUint32(0, 0, false);
        v.setUint32(4, num, false);
        return b;
    }

    fab.addEventListener('click', () => {
        fab.classList.toggle('active');
        fabMenu.classList.toggle('hidden');
    });

    fabMenu.addEventListener('click', (e) => {
        const button = e.target.closest('.fab-menu-item');
        if (!button) return;
        const action = button.dataset.action;
        if (action === 'manual') {
            addAccountModal.classList.remove('hidden');
        } else if (action === 'import') {
            importFileInput.click();
        }
        fab.classList.remove('active');
        fabMenu.classList.add('hidden');
    });

    addAccountModal.querySelector('[data-action="cancel"]').addEventListener('click', () => addAccountModal.classList.add('hidden'));
    addAccountModal.querySelector('[data-action="add"]').addEventListener('click', async () => {
        const issuer = document.getElementById('manual-issuer').value.trim();
        const secret = document.getElementById('manual-secret').value.trim().replace(/\s/g, '');
        if (!issuer || !secret) return;
        decryptedAccounts.push({ id: crypto.randomUUID(), issuer, secret });
        await saveVault();
        renderAccounts();
        addAccountModal.classList.add('hidden');
        document.getElementById('manual-issuer').value = '';
        document.getElementById('manual-secret').value = '';
    });

    actionModal.addEventListener('click', async (e) => {
        const button = e.target.closest('button');
        if (!button) return;
        const action = button.dataset.action;
        const accountId = actionModal.dataset.id;
        const accountIndex = decryptedAccounts.findIndex(acc => acc.id === accountId);
        if (accountIndex === -1) return;

        if (action === 'save') {
            const newIssuer = actionModal.querySelector('#edit-issuer').value.trim();
            if (newIssuer) {
                decryptedAccounts[accountIndex].issuer = newIssuer;
                await saveVault();
                renderAccounts();
            }
            actionModal.classList.add('hidden');
        } else if (action === 'copy-code') {
            const card = document.querySelector(`.account-card[data-id="${accountId}"]`);
            if (card) {
                const codeEl = card.querySelector('.code');
                const rawToken = codeEl.textContent.replace(/\s/g, '');
                if (rawToken && rawToken !== '000000' && rawToken !== 'Error') {
                    await copyToClipboard(rawToken, null);
                }
            }
        } else if (action === 'delete') {
            actionModal.classList.add('hidden');
            const confirmed = await showConfirmModal('Delete Account?', `This will permanently delete "${decryptedAccounts[accountIndex].issuer}". This action cannot be undone.`);
            if (confirmed) {
                decryptedAccounts.splice(accountIndex, 1);
                await saveVault();
                renderAccounts();
            }
        }
    });

    importFileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = async (event) => {
            try {
                const importedData = JSON.parse(event.target.result);
                if (!importedData.items) throw new Error("Invalid Bitwarden format.");
                const newAccounts = importedData.items
                    .filter(item => item.login && item.login.totp)
                    .map(item => {
                        const url = new URL(item.login.totp);
                        return {
                            id: crypto.randomUUID(),
                            issuer: url.searchParams.get('issuer') || item.name,
                            secret: url.searchParams.get('secret')
                        };
                    });
                decryptedAccounts.push(...newAccounts);
                await saveVault();
                renderAccounts();
                showToast(`Successfully imported ${newAccounts.length} accounts.`);
            } catch (error) {
                showToast(`Import failed: ${error.message}`);
            }
        };
        reader.readAsText(file);
        importFileInput.value = '';
    });

    async function init() {
        try {
            const response = await fetch('/api/vault');
            if (response.status === 404) {
                UIRenderer.showSetup();
            } else if (response.ok) {
                UIRenderer.showLogin();
            } else {
                throw new Error('Failed to check vault status.');
            }
        } catch (error) {
            authModalContent.innerHTML = `<h2>Error</h2><p>Could not connect to the server. Please ensure it's running and refresh the page.</p>`;
        }
    }

    init();
});
