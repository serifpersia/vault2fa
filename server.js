const express = require('express');
const fs = require('fs').promises;
const cors = require('cors');

const app = express();
const PORT = 3000;
const VAULT_FILE = 'accounts.vault';

app.use(cors());
app.use(express.static('public'));
app.use(express.json({ limit: '5mb' }));

app.get('/api/vault', async (req, res) => {
    try {
        const data = await fs.readFile(VAULT_FILE, 'utf-8');
        res.json(JSON.parse(data));
    } catch (error) {
        if (error.code === 'ENOENT') {
            return res.status(404).json({ error: 'Vault not found.' });
        }
        res.status(500).json({ error: 'Failed to read vault.' });
    }
});

app.post('/api/vault', async (req, res) => {
    try {
        await fs.writeFile(VAULT_FILE, JSON.stringify(req.body, null, 2));
        res.status(200).json({ success: true, message: 'Vault saved.' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save vault.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
