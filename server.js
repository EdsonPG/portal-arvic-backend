// ============================================================================
// SERVIDOR BACKEND PARA PORTAL ARVIC
// API REST para gestión de usuarios, empresas, proyectos, soportes y reportes
// ============================================================================

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// Importar modelos
const {
  User,
  Company,
  Project,
  Support,
  Module,
  Assignment,
  ProjectAssignment,
  TaskAssignment,
  Report,
  Tarifario
} = require('./models');

// ============================================================================
// CONFIGURACIÓN DEL SERVIDOR
// ============================================================================

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================================
// CONFIGURACIÓN DE CORS MEJORADA
// ============================================================================

const allowedOrigins = [
  'http://localhost:3000',
  'https://portal-arvic-v1-production.up.railway.app',
  process.env.FRONTEND_URL
].filter(Boolean);

console.log('🔐 CORS configurado para los siguientes orígenes:');
allowedOrigins.forEach(origin => console.log(`   ✅ ${origin}`));

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) {
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      console.log(`✅ Origen permitido: ${origin}`);
      callback(null, true);
    } else {
      console.log(`❌ Origen bloqueado por CORS: ${origin}`);
      callback(new Error('No permitido por CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// ============================================================================
// CONEXIÓN A MONGODB
// ============================================================================

mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ Conectado a MongoDB Atlas'))
.catch(err => console.error('❌ Error conectando a MongoDB:', err));

// ============================================================================
// ⚠️ ENDPOINTS TEMPORALES DE SETUP (ELIMINAR DESPUÉS DE USAR)
// ============================================================================

// Crear usuario admin
app.post('/api/setup/create-admin', async (req, res) => {
  try {
    const existingAdmin = await User.findOne({ userId: 'admin' });
    
    if (existingAdmin) {
      return res.json({
        success: false,
        message: 'El usuario admin ya existe',
        userInfo: {
          userId: existingAdmin.userId,
          name: existingAdmin.name,
          email: existingAdmin.email,
          role: existingAdmin.role,
          isActive: existingAdmin.isActive
        }
      });
    }
    
    const password = 'hperez1402.';
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const adminUser = new User({
      userId: 'admin',
      name: 'Administrador Principal',
      email: 'admin@grupoitarvic.com',
      password: hashedPassword,
      role: 'admin',
      isActive: true
    });
    
    await adminUser.save();
    
    res.json({
      success: true,
      message: '✅ Usuario admin creado exitosamente',
      credentials: {
        userId: 'admin',
        password: 'hperez1402.',
        role: 'admin'
      },
      note: '⚠️ IMPORTANTE: Elimina el endpoint /api/setup/create-admin del código por seguridad'
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Verificar si existe admin
app.get('/api/setup/check-admin', async (req, res) => {
  try {
    const admin = await User.findOne({ userId: 'admin' });
    
    if (!admin) {
      return res.json({
        success: false,
        message: 'Usuario admin no existe',
        exists: false
      });
    }
    
    res.json({
      success: true,
      exists: true,
      userInfo: {
        userId: admin.userId,
        name: admin.name,
        email: admin.email,
        role: admin.role,
        isActive: admin.isActive,
        createdAt: admin.createdAt
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token no proporcionado' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Token inválido' });
    }
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Acceso denegado. Solo administradores.' });
  }
  next();
}

// ============================================================================
// RUTAS DE AUTENTICACIÓN
// ============================================================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { userId, password } = req.body;

    const user = await User.findOne({
      $or: [{ userId: userId }, { email: userId }]
    });

    if (!user) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Usuario inactivo' });
    }

    const token = jwt.sign(
      { userId: user.userId, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      success: true,
      token: token,
      user: {
        id: user.userId,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ success: false, message: 'Error en el servidor' });
  }
});

app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.user.userId });
    if (!user) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    res.json({
      success: true,
      user: {
        id: user.userId,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error en el servidor' });
  }
});

// ============================================================================
// RUTAS DE USUARIOS
// ============================================================================

app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json({ success: true, users: users });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, email, role } = req.body;

    const lastUser = await User.findOne().sort({ userId: -1 });
    const nextId = lastUser ? (parseInt(lastUser.userId) + 1).toString().padStart(4, '0') : '0001';

    const password = `cons${nextId}.`;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      userId: nextId,
      name: name,
      email: email || '',
      password: hashedPassword,
      role: role || 'consultor'
    });

    await newUser.save();

    res.json({
      success: true,
      user: {
        id: newUser.userId,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        password: password
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/users/:userId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const user = await User.findOneAndUpdate(
      { userId: req.params.userId },
      { ...req.body, updatedAt: Date.now() },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    res.json({ success: true, user: user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/users/:userId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const user = await User.findOneAndDelete({ userId: req.params.userId });
    if (!user) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    await Assignment.deleteMany({ consultorId: req.params.userId });
    await ProjectAssignment.deleteMany({ consultorId: req.params.userId });
    await TaskAssignment.deleteMany({ consultorId: req.params.userId });

    res.json({ success: true, message: 'Usuario eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE EMPRESAS
// ============================================================================

app.get('/api/companies', authenticateToken, async (req, res) => {
  try {
    const companies = await Company.find();
    res.json({ success: true, companies: companies });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/companies', authenticateToken, isAdmin, async (req, res) => {
  try {
    const lastCompany = await Company.findOne().sort({ companyId: -1 });
    const nextId = lastCompany ? (parseInt(lastCompany.companyId) + 1).toString().padStart(4, '0') : '0001';

    const newCompany = new Company({
      companyId: nextId,
      ...req.body
    });

    await newCompany.save();
    res.json({ success: true, company: newCompany });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/companies/:companyId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const company = await Company.findOneAndUpdate(
      { companyId: req.params.companyId },
      req.body,
      { new: true }
    );
    res.json({ success: true, company: company });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/companies/:companyId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Company.findOneAndDelete({ companyId: req.params.companyId });
    await Assignment.deleteMany({ companyId: req.params.companyId });
    await ProjectAssignment.deleteMany({ companyId: req.params.companyId });
    res.json({ success: true, message: 'Empresa eliminada correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE PROYECTOS, SOPORTES, MÓDULOS
// ============================================================================

app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const projects = await Project.find();
    res.json({ success: true, projects: projects });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/projects', authenticateToken, isAdmin, async (req, res) => {
  try {
    const lastProject = await Project.findOne().sort({ projectId: -1 });
    const nextId = lastProject ? (parseInt(lastProject.projectId) + 1).toString().padStart(4, '0') : '0001';

    const newProject = new Project({
      projectId: nextId,
      ...req.body
    });

    await newProject.save();
    res.json({ success: true, project: newProject });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/supports', authenticateToken, async (req, res) => {
  try {
    const supports = await Support.find();
    res.json({ success: true, supports: supports });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/supports', authenticateToken, isAdmin, async (req, res) => {
  try {
    const lastSupport = await Support.findOne().sort({ supportId: -1 });
    const nextId = lastSupport ? (parseInt(lastSupport.supportId) + 1).toString().padStart(4, '0') : '0001';

    const newSupport = new Support({
      supportId: nextId,
      ...req.body
    });

    await newSupport.save();
    res.json({ success: true, support: newSupport });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/modules', authenticateToken, async (req, res) => {
  try {
    const modules = await Module.find();
    res.json({ success: true, modules: modules });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/modules', authenticateToken, isAdmin, async (req, res) => {
  try {
    const lastModule = await Module.findOne().sort({ moduleId: -1 });
    const nextId = lastModule ? (parseInt(lastModule.moduleId) + 1).toString().padStart(4, '0') : '0001';

    const newModule = new Module({
      moduleId: nextId,
      ...req.body
    });

    await newModule.save();
    res.json({ success: true, module: newModule });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE ASIGNACIONES
// ============================================================================

app.get('/api/assignments/user/:userId', authenticateToken, async (req, res) => {
  try {
    const supportAssignments = await Assignment.find({
      consultorId: req.params.userId,
      isActive: true
    });

    const projectAssignments = await ProjectAssignment.find({
      consultorId: req.params.userId,
      isActive: true
    });

    const taskAssignments = await TaskAssignment.find({
      consultorId: req.params.userId,
      isActive: true
    });

    res.json({
      success: true,
      assignments: {
        supports: supportAssignments,
        projects: projectAssignments,
        tasks: taskAssignments
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/assignments', authenticateToken, isAdmin, async (req, res) => {
  try {
    const lastAssignment = await Assignment.findOne().sort({ assignmentId: -1 });
    const nextId = lastAssignment ? (parseInt(lastAssignment.assignmentId) + 1).toString().padStart(4, '0') : '0001';

    const newAssignment = new Assignment({
      assignmentId: nextId,
      ...req.body
    });

    await newAssignment.save();

    const tarifaId = `tarifa_${nextId}`;
    const newTarifa = new Tarifario({
      tarifaId: tarifaId,
      idAsignacion: nextId,
      tipo: 'soporte',
      ...req.body
    });
    await newTarifa.save();

    res.json({ success: true, assignment: newAssignment });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE REPORTES
// ============================================================================

app.get('/api/reports', authenticateToken, isAdmin, async (req, res) => {
  try {
    const reports = await Report.find().sort({ createdAt: -1 });
    res.json({ success: true, reports: reports });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/reports/user/:userId', authenticateToken, async (req, res) => {
  try {
    const reports = await Report.find({ userId: req.params.userId }).sort({ createdAt: -1 });
    res.json({ success: true, reports: reports });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/reports', authenticateToken, async (req, res) => {
  try {
    const lastReport = await Report.findOne().sort({ reportId: -1 });
    const nextId = lastReport ? (parseInt(lastReport.reportId) + 1).toString().padStart(4, '0') : '0001';

    const newReport = new Report({
      reportId: nextId,
      userId: req.user.userId,
      ...req.body
    });

    await newReport.save();
    res.json({ success: true, report: newReport });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/reports/:reportId/status', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, feedback } = req.body;

    const report = await Report.findOneAndUpdate(
      { reportId: req.params.reportId },
      {
        status: status,
        feedback: feedback || '',
        approvedBy: status === 'Aprobado' ? req.user.userId : null,
        approvedAt: status === 'Aprobado' ? Date.now() : null,
        updatedAt: Date.now()
      },
      { new: true }
    );

    res.json({ success: true, report: report });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTA DE HEALTH CHECK
// ============================================================================

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Portal ARVIC API funcionando correctamente',
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// INICIALIZACIÓN DEL SERVIDOR
// ============================================================================

app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en puerto ${PORT}`);
  console.log(`🌍 Entorno: ${process.env.NODE_ENV}`);
  console.log(`🔗 API: http://localhost:${PORT}/api`);
});

process.on('unhandledRejection', (err) => {
  console.error('❌ Error no manejado:', err);
  process.exit(1);
});