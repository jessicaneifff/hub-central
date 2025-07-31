// 1. Importações
require('dotenv').config(); // Carrega as variáveis de ambiente do .env
const express = require('express');
const mysql = require('mysql2/promise'); // Usando a versão com Promises
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// 2. Inicialização do App Express
const app = express();
app.use(cors()); 
app.use(express.json());

// =======================================================
// SERVINDO ARQUIVOS ESTÁTICOS (FRONT-END)
// =======================================================
// Esta linha diz ao Express para entregar os arquivos .html, .css, .js da pasta atual.
app.use(express.static(__dirname));

// 3. Configuração da Conexão com o Banco de Dados
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// =======================================================
// LOG DE DIAGNÓSTICO: Verificando a chave secreta
// =======================================================
console.log(`[DEBUG] A chave JWT_SECRET está carregada? ${process.env.JWT_SECRET ? 'Sim' : 'NÃO!'}`);


// =======================================================
// ROTA: Enviar configurações do .env para o Front-end
// =======================================================
app.get('/api/config', (req, res) => {
    res.json({
        showNotification: process.env.SHOW_NOTIFICATION === 'true',
        notificationMessage: process.env.NOTIFICATION_MESSAGE,
        apiUrl: process.env.API_URL
    });
});

// 4. Rota de Login (o coração da autenticação)
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'E-mail e senha são obrigatórios.' });
        }

        const [rows] = await dbPool.execute('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        const user = rows[0];
        
        console.log('[LOGIN DEBUG] Objeto "user" recebido do banco:', user);
        
        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        const token = jwt.sign(
            { id: user.user_id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '365d' }
        );
        
        console.log(`[LOGIN SUCESSO] Token gerado para o usuário: ${user.email}`);

        res.status(200).json({ 
            message: 'Login bem-sucedido!', 
            token: token,
            user: {
                id: user.user_id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Erro no servidor durante o login:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// =======================================================
// MIDDLEWARE DE AUTENTICAÇÃO (COM DIAGNÓSTICOS)
// =======================================================
function authenticateToken(req, res, next) {
    console.log('\n--- [MIDDLEWARE] Verificando autenticação ---');
    const authHeader = req.headers['authorization'];
    console.log('[MIDDLEWARE] Cabeçalho de Autorização recebido:', authHeader);

    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        console.log('[MIDDLEWARE FALHA] Token não encontrado. Acesso negado (401).');
        return res.sendStatus(401);
    }

    console.log('[MIDDLEWARE] Token extraído:', token);

    jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
        if (err) {
            console.error('[MIDDLEWARE FALHA] Erro na verificação do JWT:', err.message);
            console.log('[MIDDLEWARE FALHA] Acesso proibido (403).');
            return res.sendStatus(403);
        }
        
        console.log('[MIDDLEWARE SUCESSO] Token verificado com sucesso. Payload:', userPayload);
        req.user = userPayload;
        next();
    });
}

// =======================================================
// ROTA PROTEGIDA DO DASHBOARD
// =======================================================
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    console.log('--- [ROTA /api/dashboard] Acesso permitido pelo middleware ---');
    try {
        const userId = req.user.id; 
        console.log(`[ROTA /api/dashboard] Buscando dados para o userId: ${userId}`);

        if (!userId) {
            console.log('[ROTA /api/dashboard] ERRO: ID do usuário não encontrado no token.');
            return res.status(400).json({ message: "ID do usuário inválido no token." });
        }

        const [rows] = await dbPool.execute('SELECT user_id as id, name, email FROM users WHERE user_id = ?', [userId]);

        if (rows.length === 0) {
            console.log(`[ROTA /api/dashboard] Usuário com id ${userId} não encontrado no banco.`);
            return res.status(404).json({ message: "Usuário do token não encontrado no banco." });
        }

        const userData = rows[0];
        console.log(`[ROTA /api/dashboard] Dados encontrados. Enviando para o front-end.`);
        res.json({
            message: "Dados do dashboard carregados com sucesso!",
            user: userData
        });

    } catch (error) {
        console.error('Erro na rota do dashboard:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// =======================================================
// ROTA SSO (CORRIGIDA PARA USAR O BANCO DE DADOS)
// =======================================================
app.get('/sso/redirect', authenticateToken, async (req, res) => {
    try {
        const appName = req.query.app; // ex: 'notify'
        const user = req.user;

        // 1. Busca a configuração de SSO do banco de dados
        const [settingsRows] = await dbPool.execute("SELECT `value` FROM `settings` WHERE `key` = 'sso'");

        if (settingsRows.length === 0) {
            return res.status(500).json({ message: 'Configuração de SSO não encontrada no banco de dados.' });
        }

        const ssoConfig = JSON.parse(settingsRows[0].value);
        
        // 2. Encontra a aplicação de destino na configuração pelo nome
        const targetAppConfig = Object.values(ssoConfig.websites).find(
            site => site.name.toLowerCase() === appName.toLowerCase()
        );

        if (!targetAppConfig) {
            return res.status(400).json({ message: 'Aplicação de destino inválida ou não configurada.' });
        }

        // 3. Busca os dados do usuário atual
        const [userRows] = await dbPool.execute('SELECT user_id, email, name FROM users WHERE user_id = ?', [user.id]);
        if (userRows.length === 0) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        const userData = userRows[0];

        // 4. Gera o token SSO assinado com a API Key do banco de dados
        const ssoToken = jwt.sign(
            {
                user_id: userData.user_id,
                email: userData.email,
                name: userData.name
            },
            targetAppConfig.api_key,
            { expiresIn: '1m' }
        );

        // 5. Constrói a URL de redirecionamento e envia como JSON
        const redirectUrl = `${targetAppConfig.url}/sso/login?token=${ssoToken}`;
        
        console.log(`[SSO] Gerando URL de redirecionamento para ${appName}: ${redirectUrl}`);
        
        res.json({ redirectUrl });

    } catch (error) {
        console.error('Erro durante o redirecionamento SSO:', error);
        res.status(500).json({ message: 'Ocorreu um erro interno durante o processo de SSO.' });
    }
});

// =======================================================
// ROTA "CATCH-ALL" PARA ERROS 404 (Página não encontrada)
// =======================================================
app.use((req, res, next) => {
    res.status(404).sendFile(__dirname + '/404.html');
});

// 5. Iniciando o Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
