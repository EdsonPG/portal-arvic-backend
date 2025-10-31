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
// CONFIGURACIÓN DE TRUST PROXY PARA RAILWAY
// ============================================================================
// Railway usa un proxy reverso, necesitamos confiar en él
app.set('trust proxy', true);

// ============================================================================
// CONFIGURACIÓN DE CORS ACTUALIZADA
// ============================================================================

const allowedOrigins = [
  'http://localhost:3000',                                      // Desarrollo local
  'http://127.0.0.1:3000',                                      // Desarrollo local alternativo
  'https://portal-arvic-v1-production.up.railway.app',         // Frontend en Railway
  process.env.FRONTEND_URL                                      // Variable de entorno adicional
].filter(Boolean); // Eliminar valores undefined

console.log('🔐 CORS configurado para los siguientes orígenes:');
allowedOrigins.forEach(origin => console.log(`   ✅ ${origin}`));

const corsOptions = {
  origin: function (origin, callback) {
    // Permitir peticiones sin origin (Postman, apps móviles, Thunder Client, etc.)
    if (!origin) {
      console.log('✅ Petición sin origin (permitida)');
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

// Rate limiting para prevenir ataques (ajustado para producción)
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 200, // máximo 200 requests por minuto
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Demasiadas peticiones desde esta IP, por favor intenta de nuevo más tarde.',
  skip: (req) => {
    // No limitar health checks
    return req.path === '/api/health';
  }
});
app.use('/api/', limiter);

// ============================================================================
// CONEXIÓN A MONGODB
// ============================================================================

console.log('🔄 Intentando conectar a MongoDB...');
console.log('📍 URI:', process.env.MONGODB_URI ? 'Configurada ✅' : 'NO configurada ❌');

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
  console.log('✅ Conectado a MongoDB Atlas');
  console.log('📊 Estado de conexión:', mongoose.connection.readyState);
})
.catch(err => {
  console.error('❌ Error conectando a MongoDB:', err);
  console.error('💡 Verifica tu variable MONGODB_URI en Railway');
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

// Middleware para verificar rol admin
function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Acceso denegado. Solo administradores.' });
  }
  next();
}

// ============================================================================
// RUTA DE HEALTH CHECK
// ============================================================================

app.get('/api/health', (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStatus = {
    0: 'desconectado',
    1: 'conectado',
    2: 'conectando',
    3: 'desconectando'
  };
  
  res.json({ 
    success: true, 
    message: 'Portal ARVIC API funcionando correctamente',
    timestamp: new Date().toISOString(),
    mongodb: {
      status: dbStatus[dbState] || 'desconocido',
      readyState: dbState
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

// ============================================================================
// RUTAS DE AUTENTICACIÓN
// ============================================================================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { userId, password } = req.body;

    // Buscar usuario por userId o email
    const user = await User.findOne({
      $or: [{ userId: userId }, { email: userId }]
    });

    if (!user) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    // Verificar contraseña
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    // Verificar que el usuario esté activo
    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Usuario inactivo' });
    }

    // Generar token JWT
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

// Verificar token
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
// RUTAS DE USUARIOS (Solo Admin)
// ============================================================================

// Obtener todos los usuarios
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    console.log('📊 Solicitando lista de usuarios...');
    const users = await User.find().select('-password');
    console.log(`✅ Usuarios encontrados: ${users.length}`);
    res.json({ success: true, users: users });
  } catch (error) {
    console.error('❌ Error obteniendo usuarios:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Crear usuario
app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, email, role } = req.body;

    // Obtener el siguiente ID de usuario
    const lastUser = await User.findOne().sort({ userId: -1 });
    const nextId = lastUser ? (parseInt(lastUser.userId) + 1).toString().padStart(4, '0') : '0001';

    // Generar contraseña temporal
    const tempPassword = 'arvic' + nextId;
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

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
      user: { ...newUser.toObject(), password: undefined },
      tempPassword: tempPassword 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/users/:userId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const user = await User.findOneAndUpdate(
      { userId: req.params.userId },
      { $set: req.body, updatedAt: new Date() },
      { new: true }
    ).select('-password');
    res.json({ success: true, user: user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/users/:userId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await User.findOneAndDelete({ userId: req.params.userId });
    res.json({ success: true, message: 'Usuario eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE EMPRESAS (Solo Admin)
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
// RUTAS DE PROYECTOS
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

app.put('/api/projects/:projectId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const project = await Project.findOneAndUpdate(
      { projectId: req.params.projectId },
      req.body,
      { new: true }
    );
    res.json({ success: true, project: project });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/projects/:projectId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Project.findOneAndDelete({ projectId: req.params.projectId });
    await ProjectAssignment.deleteMany({ projectId: req.params.projectId });
    res.json({ success: true, message: 'Proyecto eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE SOPORTES
// ============================================================================

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

app.put('/api/supports/:supportId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const support = await Support.findOneAndUpdate(
      { supportId: req.params.supportId },
      req.body,
      { new: true }
    );
    res.json({ success: true, support: support });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/supports/:supportId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Support.findOneAndDelete({ supportId: req.params.supportId });
    await Assignment.deleteMany({ supportId: req.params.supportId });
    res.json({ success: true, message: 'Soporte eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE MÓDULOS
// ============================================================================

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

app.put('/api/modules/:moduleId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const module = await Module.findOneAndUpdate(
      { moduleId: req.params.moduleId },
      req.body,
      { new: true }
    );
    res.json({ success: true, module: module });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/modules/:moduleId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Module.findOneAndDelete({ moduleId: req.params.moduleId });
    res.json({ success: true, message: 'Módulo eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE ASIGNACIONES (SOPORTES)
// ============================================================================

app.get('/api/assignments', authenticateToken, async (req, res) => {
  try {
    const assignments = await Assignment.find();
    res.json({ success: true, assignments: assignments });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/assignments/user/:userId', authenticateToken, async (req, res) => {
  try {
    const assignments = await Assignment.find({ consultorId: req.params.userId, isActive: true });
    res.json({ success: true, assignments: assignments });
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

    // Crear entrada en tarifario
    const tarifario = new Tarifario({
      tarifaId: `TAR-${nextId}`,
      idAsignacion: nextId,
      tipo: 'soporte',
      consultorId: req.body.consultorId,
      clienteId: req.body.companyId,
      trabajoId: req.body.supportId,
      modulo: req.body.moduleId,
      costoConsultor: req.body.tarifaConsultor || 0,
      costoCliente: req.body.tarifaCliente || 0,
      margen: (req.body.tarifaCliente || 0) - (req.body.tarifaConsultor || 0)
    });

    await tarifario.save();

    res.json({ success: true, assignment: newAssignment });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/assignments/:assignmentId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const assignment = await Assignment.findOneAndUpdate(
      { assignmentId: req.params.assignmentId },
      req.body,
      { new: true }
    );
    res.json({ success: true, assignment: assignment });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/assignments/:assignmentId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Assignment.findOneAndDelete({ assignmentId: req.params.assignmentId });
    await Report.deleteMany({ assignmentId: req.params.assignmentId });
    res.json({ success: true, message: 'Asignación eliminada correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE ASIGNACIONES DE PROYECTOS
// ============================================================================

app.get('/api/assignments/projects', authenticateToken, async (req, res) => {
  try {
    const projectAssignments = await ProjectAssignment.find();
    res.json({ success: true, assignments: projectAssignments });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/assignments/projects/user/:userId', authenticateToken, async (req, res) => {
  try {
    const projectAssignments = await ProjectAssignment.find({ 
      consultorId: req.params.userId, 
      isActive: true 
    });
    res.json({ success: true, assignments: projectAssignments });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/assignments/projects', authenticateToken, isAdmin, async (req, res) => {
  try {
    const lastAssignment = await ProjectAssignment.findOne().sort({ projectAssignmentId: -1 });
    const nextId = lastAssignment ? 
      (parseInt(lastAssignment.projectAssignmentId) + 1).toString().padStart(4, '0') : '0001';

    const newProjectAssignment = new ProjectAssignment({
      projectAssignmentId: nextId,
      ...req.body
    });

    await newProjectAssignment.save();

    // Crear entrada en tarifario
    const tarifario = new Tarifario({
      tarifaId: `TAR-P-${nextId}`,
      idAsignacion: nextId,
      tipo: 'proyecto',
      consultorId: req.body.consultorId,
      clienteId: req.body.companyId,
      trabajoId: req.body.projectId,
      modulo: req.body.moduleId,
      costoConsultor: req.body.tarifaConsultor || 0,
      costoCliente: req.body.tarifaCliente || 0,
      margen: (req.body.tarifaCliente || 0) - (req.body.tarifaConsultor || 0)
    });

    await tarifario.save();

    res.json({ success: true, assignment: newProjectAssignment });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/assignments/projects/:projectAssignmentId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await ProjectAssignment.findOneAndDelete({ projectAssignmentId: req.params.projectAssignmentId });
    await Report.deleteMany({ assignmentId: req.params.projectAssignmentId });
    res.json({ success: true, message: 'Asignación de proyecto eliminada' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE TAREAS
// ============================================================================

app.get('/api/assignments/tasks', authenticateToken, async (req, res) => {
  try {
    const taskAssignments = await TaskAssignment.find();
    res.json({ success: true, assignments: taskAssignments });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/assignments/tasks/user/:userId', authenticateToken, async (req, res) => {
  try {
    const taskAssignments = await TaskAssignment.find({ 
      consultorId: req.params.userId,
      isActive: true
    });
    res.json({ success: true, assignments: taskAssignments });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/assignments/tasks', authenticateToken, isAdmin, async (req, res) => {
  try {
    const lastTask = await TaskAssignment.findOne().sort({ taskId: -1 });
    const nextId = lastTask ? (parseInt(lastTask.taskId) + 1).toString().padStart(4, '0') : '0001';

    const newTask = new TaskAssignment({
      taskId: nextId,
      ...req.body
    });

    await newTask.save();

    // Crear entrada en tarifario
    const tarifario = new Tarifario({
      tarifaId: `TAR-T-${nextId}`,
      idAsignacion: nextId,
      tipo: 'tarea',
      consultorId: req.body.consultorId,
      clienteId: req.body.companyId,
      trabajoId: req.body.linkedSupportId,
      modulo: req.body.moduleId,
      costoConsultor: req.body.tarifaConsultor || 0,
      costoCliente: req.body.tarifaCliente || 0,
      margen: (req.body.tarifaCliente || 0) - (req.body.tarifaConsultor || 0)
    });

    await tarifario.save();

    res.json({ success: true, task: newTask });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/assignments/tasks/:taskId', authenticateToken, async (req, res) => {
  try {
    const task = await TaskAssignment.findOneAndUpdate(
      { taskId: req.params.taskId },
      req.body,
      { new: true }
    );
    res.json({ success: true, task: task });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/assignments/tasks/:taskId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await TaskAssignment.findOneAndDelete({ taskId: req.params.taskId });
    res.json({ success: true, message: 'Tarea eliminada correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE REPORTES
// ============================================================================

app.get('/api/reports', authenticateToken, async (req, res) => {
  try {
    const reports = await Report.find();
    res.json({ success: true, reports: reports });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/reports/user/:userId', authenticateToken, async (req, res) => {
  try {
    const reports = await Report.find({ userId: req.params.userId });
    res.json({ success: true, reports: reports });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/reports/assignment/:assignmentId', authenticateToken, async (req, res) => {
  try {
    const reports = await Report.find({ assignmentId: req.params.assignmentId });
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
      ...req.body
    });

    await newReport.save();
    res.json({ success: true, report: newReport });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/reports/:reportId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const report = await Report.findOneAndUpdate(
      { reportId: req.params.reportId },
      req.body,
      { new: true }
    );
    res.json({ success: true, report: report });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/reports/:reportId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Report.findOneAndDelete({ reportId: req.params.reportId });
    res.json({ success: true, message: 'Reporte eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS DE TARIFARIO
// ============================================================================

app.get('/api/rates', authenticateToken, async (req, res) => {
  try {
    const tarifas = await Tarifario.find();
    res.json({ success: true, tarifario: tarifas });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/rates/:tarifaId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const tarifa = await Tarifario.findOneAndUpdate(
      { tarifaId: req.params.tarifaId },
      { ...req.body, updatedAt: new Date() },
      { new: true }
    );
    res.json({ success: true, tarifa: tarifa });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// RUTAS ADICIONALES
// ============================================================================

// Resumen de consultores
app.get('/api/users/consultants/summary', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find({ role: 'consultor' }).select('-password');
    const assignments = await Assignment.find();
    const projectAssignments = await ProjectAssignment.find();
    const taskAssignments = await TaskAssignment.find();
    
    const summary = users.map(user => {
      const userAssignments = assignments.filter(a => a.consultorId === user.userId);
      const userProjects = projectAssignments.filter(p => p.consultorId === user.userId);
      const userTasks = taskAssignments.filter(t => t.consultorId === user.userId);
      
      return {
        userId: user.userId,
        name: user.name,
        totalAssignments: userAssignments.length + userProjects.length + userTasks.length,
        supportAssignments: userAssignments.length,
        projectAssignments: userProjects.length,
        taskAssignments: userTasks.length
      };
    });
    
    res.json({ success: true, summary: summary });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Reportes generados (aprobados)
app.get('/api/reports/generated', authenticateToken, async (req, res) => {
  try {
    const approvedReports = await Report.find({ status: 'Aprobado' });
    res.json({ success: true, reports: approvedReports });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================================
// INICIAR SERVIDOR
// ============================================================================

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📍 API disponible en: http://localhost:${PORT}/api`);
  console.log(`🔐 CORS habilitado para:`, allowedOrigins);
});