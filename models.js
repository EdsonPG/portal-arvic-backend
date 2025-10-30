const mongoose = require('mongoose');

// ============================================================================
// MODELO DE USUARIO
// ============================================================================
const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true }, // ID numérico como string
  name: { type: String, required: true },
  email: { type: String, sparse: true }, // No todos tienen email
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'consultor'], default: 'consultor' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// ============================================================================
// MODELO DE EMPRESA/CLIENTE
// ============================================================================
const companySchema = new mongoose.Schema({
  companyId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: { type: String, default: '' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// ============================================================================
// MODELO DE PROYECTO
// ============================================================================
const projectSchema = new mongoose.Schema({
  projectId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: { type: String, default: '' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// ============================================================================
// MODELO DE SOPORTE
// ============================================================================
const supportSchema = new mongoose.Schema({
  supportId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: { type: String, default: '' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// ============================================================================
// MODELO DE MÓDULO
// ============================================================================
const moduleSchema = new mongoose.Schema({
  moduleId: { type: String, required: true, unique: true },
  code: { type: String, required: true },
  name: { type: String, required: true },
  description: { type: String, default: '' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// ============================================================================
// MODELO DE ASIGNACIÓN (SOPORTE)
// ============================================================================
const assignmentSchema = new mongoose.Schema({
  assignmentId: { type: String, required: true, unique: true },
  consultorId: { type: String, required: true },
  companyId: { type: String, required: true },
  supportId: { type: String, required: true },
  moduleId: { type: String, required: true },
  tarifaConsultor: { type: Number, default: 0 },
  tarifaCliente: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// ============================================================================
// MODELO DE ASIGNACIÓN DE PROYECTO
// ============================================================================
const projectAssignmentSchema = new mongoose.Schema({
  assignmentId: { type: String, required: true, unique: true },
  consultorId: { type: String, required: true },
  companyId: { type: String, required: true },
  projectId: { type: String, required: true },
  moduleId: { type: String, required: true },
  tarifaConsultor: { type: Number, default: 0 },
  tarifaCliente: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// ============================================================================
// MODELO DE TAREAS
// ============================================================================
const taskAssignmentSchema = new mongoose.Schema({
  taskId: { type: String, required: true, unique: true },
  consultorId: { type: String, required: true },
  companyId: { type: String, required: true },
  linkedSupportId: { type: String, required: true },
  moduleId: { type: String, required: true },
  descripcion: { type: String, required: true },
  tarifaConsultor: { type: Number, default: 0 },
  tarifaCliente: { type: Number, default: 0 },
  status: { type: String, enum: ['Pendiente', 'En Progreso', 'Completada'], default: 'Pendiente' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// ============================================================================
// MODELO DE REPORTES
// ============================================================================
const reportSchema = new mongoose.Schema({
  reportId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  assignmentId: { type: String, required: true },
  type: { type: String, required: true }, // 'soporte', 'proyecto', 'tarea'
  reportData: { type: mongoose.Schema.Types.Mixed, required: true }, // JSON con los datos del reporte
  status: { type: String, enum: ['Pendiente', 'Aprobado', 'Rechazado', 'Resubmitted'], default: 'Pendiente' },
  feedback: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  approvedBy: { type: String, default: null },
  approvedAt: { type: Date, default: null },
  resubmittedAt: { type: Date, default: null }
});

// ============================================================================
// MODELO DE TARIFARIO
// ============================================================================
const tarifarioSchema = new mongoose.Schema({
  tarifaId: { type: String, required: true, unique: true },
  idAsignacion: { type: String, required: true },
  modulo: { type: String, required: true },
  moduloNombre: { type: String, default: '' },
  tipo: { type: String, enum: ['soporte', 'proyecto', 'tarea'], required: true },
  consultorId: { type: String, required: true },
  consultorNombre: { type: String, default: '' },
  clienteId: { type: String, required: true },
  clienteNombre: { type: String, default: '' },
  trabajoId: { type: String, required: true },
  trabajoNombre: { type: String, default: '' },
  costoConsultor: { type: Number, default: 0 },
  costoCliente: { type: Number, default: 0 },
  margen: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Exportar todos los modelos
module.exports = {
  User: mongoose.model('User', userSchema),
  Company: mongoose.model('Company', companySchema),
  Project: mongoose.model('Project', projectSchema),
  Support: mongoose.model('Support', supportSchema),
  Module: mongoose.model('Module', moduleSchema),
  Assignment: mongoose.model('Assignment', assignmentSchema),
  ProjectAssignment: mongoose.model('ProjectAssignment', projectAssignmentSchema),
  TaskAssignment: mongoose.model('TaskAssignment', taskAssignmentSchema),
  Report: mongoose.model('Report', reportSchema),
  Tarifario: mongoose.model('Tarifario', tarifarioSchema)
};