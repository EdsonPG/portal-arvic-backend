// ============================================================================
// SCRIPT DE INICIALIZACIÓN DE LA BASE DE DATOS
// Crea el usuario administrador por defecto si no existe
// ============================================================================

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { User } = require('./models');

async function initializeDatabase() {
  try {
    console.log('🚀 Iniciando script de inicialización...');
    
    // Conectar a MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Conectado a MongoDB');

    // Verificar si existe el usuario admin
    const adminExists = await User.findOne({ userId: 'admin' });

    if (adminExists) {
      console.log('✅ Usuario admin ya existe');
    } else {
      console.log('📝 Creando usuario administrador...');
      
      // Crear usuario admin por defecto
      const hashedPassword = await bcrypt.hash('admin123', 10);
      
      const adminUser = new User({
        userId: 'admin',
        name: 'Administrador',
        email: 'admin@arvic.com',
        password: hashedPassword,
        role: 'admin',
        isActive: true
      });

      await adminUser.save();
      console.log('✅ Usuario admin creado exitosamente');
      console.log('📧 Credenciales:');
      console.log('   Usuario: admin');
      console.log('   Contraseña: admin123');
      console.log('   ⚠️  CAMBIA ESTA CONTRASEÑA DESPUÉS DEL PRIMER LOGIN');
    }

    // Verificar cantidad de usuarios
    const userCount = await User.countDocuments();
    console.log(`📊 Total de usuarios en la base de datos: ${userCount}`);

    mongoose.connection.close();
    console.log('✅ Inicialización completada');
    process.exit(0);

  } catch (error) {
    console.error('❌ Error en la inicialización:', error);
    process.exit(1);
  }
}

// Ejecutar script
initializeDatabase();