/**
 * Medical Messaging Platform - Enhanced File Upload Implementation
 * 
 * Extended multer configuration to allow uploading of various document types
 * including PDFs, Excel files, images, and other common medical document formats.
 */

const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// Ensure uploads directory exists
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Create subdirectories for different file types
const documentDir = path.join(uploadDir, 'documents');
const imageDir = path.join(uploadDir, 'images');
const spreadsheetDir = path.join(uploadDir, 'spreadsheets');
const archiveDir = path.join(uploadDir, 'archives');
const otherDir = path.join(uploadDir, 'other');

[documentDir, imageDir, spreadsheetDir, archiveDir, otherDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Define acceptable MIME types by category
const allowedMimeTypes = {
  documents: [
    'application/pdf', // PDF
    'application/msword', // DOC
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // DOCX
    'application/vnd.oasis.opendocument.text', // ODT
    'application/rtf', // RTF
    'text/plain', // TXT
    'text/markdown', // MD
    'application/vnd.ms-powerpoint', // PPT
    'application/vnd.openxmlformats-officedocument.presentationml.presentation', // PPTX
    'application/vnd.oasis.opendocument.presentation' // ODP
  ],
  images: [
    'image/jpeg', // JPG, JPEG
    'image/png', // PNG
    'image/gif', // GIF
    'image/webp', // WEBP
    'image/svg+xml', // SVG
    'image/bmp', // BMP
    'image/tiff', // TIFF
    'image/dicom' // DICOM medical images
  ],
  spreadsheets: [
    'application/vnd.ms-excel', // XLS
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // XLSX
    'application/vnd.oasis.opendocument.spreadsheet', // ODS
    'text/csv', // CSV
    'application/json', // JSON
    'text/tab-separated-values' // TSV
  ],
  archives: [
    'application/zip', // ZIP
    'application/x-rar-compressed', // RAR
    'application/x-7z-compressed', // 7Z
    'application/gzip', // GZIP
    'application/x-tar' // TAR
  ],
  medical: [
    'application/dicom', // DICOM
    'application/octet-stream', // Various binary formats including medical data
    'application/hl7-v2', // HL7 health data
    'application/fhir+json', // FHIR JSON
    'application/fhir+xml' // FHIR XML
  ],
  other: [
    'audio/mpeg', // MP3
    'audio/wav', // WAV
    'video/mp4', // MP4
    'video/webm', // WEBM
    'application/xml', // XML
    'text/html', // HTML
    'text/calendar', // ICS calendar
    'application/pgp-signature' // PGP signature for secure documents
  ]
};

// Combine all allowed MIME types
const allAllowedMimeTypes = [
  ...allowedMimeTypes.documents,
  ...allowedMimeTypes.images,
  ...allowedMimeTypes.spreadsheets,
  ...allowedMimeTypes.archives,
  ...allowedMimeTypes.medical,
  ...allowedMimeTypes.other
];

// Configure file size limits by type
const fileSizeLimits = {
  documents: 25 * 1024 * 1024, // 25MB for documents
  images: 15 * 1024 * 1024,    // 15MB for images
  spreadsheets: 20 * 1024 * 1024, // 20MB for spreadsheets
  archives: 50 * 1024 * 1024,  // 50MB for archives
  medical: 100 * 1024 * 1024,  // 100MB for medical files (like DICOM)
  other: 30 * 1024 * 1024,     // 30MB for other types
  default: 10 * 1024 * 1024    // 10MB default
};

// Function to get appropriate directory based on mimetype
const getUploadDirectory = (mimetype) => {
  if (allowedMimeTypes.documents.includes(mimetype)) return documentDir;
  if (allowedMimeTypes.images.includes(mimetype)) return imageDir;
  if (allowedMimeTypes.spreadsheets.includes(mimetype)) return spreadsheetDir;
  if (allowedMimeTypes.archives.includes(mimetype)) return archiveDir;
  if (allowedMimeTypes.medical.includes(mimetype)) return documentDir; // Store medical docs with other documents
  return otherDir;
};

// Function to get appropriate file size limit based on mimetype
const getFileSizeLimit = (mimetype) => {
  if (allowedMimeTypes.documents.includes(mimetype)) return fileSizeLimits.documents;
  if (allowedMimeTypes.images.includes(mimetype)) return fileSizeLimits.images;
  if (allowedMimeTypes.spreadsheets.includes(mimetype)) return fileSizeLimits.spreadsheets;
  if (allowedMimeTypes.archives.includes(mimetype)) return fileSizeLimits.archives;
  if (allowedMimeTypes.medical.includes(mimetype)) return fileSizeLimits.medical;
  if (allowedMimeTypes.other.includes(mimetype)) return fileSizeLimits.other;
  return fileSizeLimits.default;
};

// Set up storage engine
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = getUploadDirectory(file.mimetype);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Generate a unique filename while preserving the original extension
    const originalExt = path.extname(file.originalname);
    const fileName = `${Date.now()}-${crypto.randomBytes(16).toString('hex')}${originalExt}`;
    cb(null, fileName);
  }
});

// Create the multer instance for handling file uploads
const fileUpload = multer({
  storage,
  limits: {
    fileSize: (req, file) => getFileSizeLimit(file.mimetype)
  },
  fileFilter: (req, file, cb) => {
    // Check if the file type is allowed
    if (allAllowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${file.mimetype} is not allowed`), false);
    }
  }
});

// Extended file upload middleware to handle different upload scenarios
const configureFileUpload = () => {
  // Single file upload (default)
  const uploadSingle = fileUpload.single('file');
  
  // Multiple files upload (up to 10)
  const uploadMultiple = fileUpload.array('files', 10);
  
  // Multiple files with different field names
  const uploadFields = fileUpload.fields([
    { name: 'document', maxCount: 5 },
    { name: 'image', maxCount: 5 },
    { name: 'spreadsheet', maxCount: 3 },
    { name: 'attachment', maxCount: 10 }
  ]);
  
  return {
    single: uploadSingle,
    multiple: uploadMultiple,
    fields: uploadFields
  };
};

// Middleware to handle file upload errors
const handleFileUploadErrors = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    // Multer-specific error
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ 
        error: 'File too large', 
        message: `File exceeds the size limit. Maximum allowed: ${getFileSizeLimit(req.file?.mimetype) / (1024 * 1024)}MB` 
      });
    }
    return res.status(400).json({ error: err.code, message: err.message });
  } else if (err) {
    // Generic error
    return res.status(400).json({ error: 'File upload error', message: err.message });
  }
  next();
};

// Extended route handler for file uploads
const handleFileUpload = async (req, res) => {
  try {
    // If no file was uploaded
    if (!req.file && !req.files) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    
    const { conversationId } = req.body;
    
    // Verify user is part of this conversation
    const conversation = await Conversation.findOne({
      _id: conversationId,
      participants: req.user._id,
      organizationId: req.organizationId
    });
    
    if (!conversation) {
      return res.status(404).json({ message: 'Conversation not found' });
    }
    
    // Handle single file upload
    if (req.file) {
      const file = new File({
        originalName: req.file.originalname,
        encoding: req.file.encoding,
        mimetype: req.file.mimetype,
        size: req.file.size,
        filename: req.file.filename,
        path: req.file.path,
        uploadedBy: req.user._id,
        conversationId,
        organizationId: req.organizationId,
        category: getFileCategory(req.file.mimetype)
      });
      
      await file.save();
      
      // Generate preview URL for supported file types
      const previewUrl = generatePreviewUrl(file);
      
      return res.status(201).json({
        id: file._id,
        originalName: file.originalName,
        mimetype: file.mimetype,
        size: file.size,
        uploadedAt: file.createdAt,
        category: file.category,
        preview: previewUrl
      });
    }
    
    // Handle multiple file uploads
    if (req.files) {
      let uploadedFiles = [];
      
      // Handle array of files
      if (Array.isArray(req.files)) {
        const filePromises = req.files.map(async (fileObj) => {
          const file = new File({
            originalName: fileObj.originalname,
            encoding: fileObj.encoding,
            mimetype: fileObj.mimetype,
            size: fileObj.size,
            filename: fileObj.filename,
            path: fileObj.path,
            uploadedBy: req.user._id,
            conversationId,
            organizationId: req.organizationId,
            category: getFileCategory(fileObj.mimetype)
          });
          
          await file.save();
          
          return {
            id: file._id,
            originalName: file.originalName,
            mimetype: file.mimetype,
            size: file.size,
            uploadedAt: file.createdAt,
            category: file.category,
            preview: generatePreviewUrl(file)
          };
        });
        
        uploadedFiles = await Promise.all(filePromises);
      } 
      // Handle fields of files
      else {
        const filePromises = [];
        
        // Process each field
        Object.keys(req.files).forEach(fieldName => {
          req.files[fieldName].forEach(fileObj => {
            const filePromise = (async () => {
              const file = new File({
                originalName: fileObj.originalname,
                encoding: fileObj.encoding,
                mimetype: fileObj.mimetype,
                size: fileObj.size,
                filename: fileObj.filename,
                path: fileObj.path,
                uploadedBy: req.user._id,
                conversationId,
                organizationId: req.organizationId,
                fieldName, // Store which field it came from
                category: getFileCategory(fileObj.mimetype)
              });
              
              await file.save();
              
              return {
                id: file._id,
                originalName: file.originalName,
                mimetype: file.mimetype,
                size: file.size,
                uploadedAt: file.createdAt,
                fieldName,
                category: file.category,
                preview: generatePreviewUrl(file)
              };
            })();
            
            filePromises.push(filePromise);
          });
        });
        
        uploadedFiles = await Promise.all(filePromises);
      }
      
      return res.status(201).json({
        files: uploadedFiles,
        count: uploadedFiles.length
      });
    }
    
  } catch (error) {
    console.error('Error handling file upload:', error);
    res.status(500).json({ message: 'Internal server error during file upload' });
  }
};

// Helper function to determine file category based on mimetype
const getFileCategory = (mimetype) => {
  if (allowedMimeTypes.documents.includes(mimetype)) return 'document';
  if (allowedMimeTypes.images.includes(mimetype)) return 'image';
  if (allowedMimeTypes.spreadsheets.includes(mimetype)) return 'spreadsheet';
  if (allowedMimeTypes.archives.includes(mimetype)) return 'archive';
  if (allowedMimeTypes.medical.includes(mimetype)) return 'medical';
  if (allowedMimeTypes.other.includes(mimetype)) return 'other';
  return 'unknown';
};

// Helper function to generate preview URLs for supported file types
const generatePreviewUrl = (file) => {
  // If it's an image, we can provide a direct preview URL
  if (file.mimetype.startsWith('image/')) {
    return `/api/files/${file._id}/preview`;
  }
  
  // For PDFs, we can also provide preview
  if (file.mimetype === 'application/pdf') {
    return `/api/files/${file._id}/preview`;
  }
  
  // For other types, return null (no preview available)
  return null;
};

// Route to serve file previews
const setupFilePreviewRoute = (app) => {
  app.get('/api/files/:fileId/preview', authenticate, async (req, res) => {
    try {
      const { fileId } = req.params;
      
      const file = await File.findById(fileId);
      
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Check if user has access to this file
      const conversation = await Conversation.findOne({
        _id: file.conversationId,
        participants: req.user._id
      });
      
      if (!conversation) {
        return res.status(403).json({ message: 'Unauthorized' });
      }
      
      // For images and PDFs, serve the file directly
      if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
        res.setHeader('Content-Type', file.mimetype);
        return res.sendFile(path.resolve(file.path));
      }
      
    // For spreadsheets, we might generate a preview image or HTML table
      if (allowedMimeTypes.spreadsheets.includes(file.mimetype)) {
        // In a real implementation, you would use a library like ExcelJS, SheetJS, or a service
        // to convert the spreadsheet to HTML or an image preview
        return res.status(501).json({ message: 'Spreadsheet preview generation not implemented' });
      }
      
      // For other file types, we might show a generic icon or message
      return res.status(400).json({ message: 'Preview not available for this file type' });
    } catch (error) {
      console.error('Error serving file preview:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  // Route to download original files
  app.get('/api/files/:fileId/download', authenticate, async (req, res) => {
    try {
      const { fileId } = req.params;
      
      const file = await File.findById(fileId);
      
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Check if user has access to this file
      const conversation = await Conversation.findOne({
        _id: file.conversationId,
        participants: req.user._id
      });
      
      if (!conversation) {
        return res.status(403).json({ message: 'Unauthorized' });
      }
      
      // Log the download in the audit trail
      const auditEntry = new AuditLog({
        action: 'FILE_DOWNLOAD',
        userId: req.user._id,
        resourceType: 'file',
        resourceId: file._id.toString(),
        details: {
          filename: file.originalName,
          mimetype: file.mimetype,
          size: file.size
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        organizationId: req.organizationId
      });
      
      await auditEntry.save();
      
      // Set the appropriate headers for download
      res.setHeader('Content-Type', file.mimetype);
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.originalName)}"`);
      
      // Send the file
      return res.sendFile(path.resolve(file.path));
    } catch (error) {
      console.error('Error downloading file:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
};

// Set up virus scanning for uploaded files
const setupVirusScan = () => {
  // This would integrate with a virus scanning service
  // Options include ClamAV (open source), VirusTotal API, or other services
  
  const scanFile = async (filePath) => {
    console.log(`Scanning file for viruses: ${filePath}`);
    // In a real implementation, this would connect to your virus scanning solution
    // and return a promise that resolves with the scan results
    
    // Mock implementation for demonstration
    return new Promise((resolve) => {
      setTimeout(() => {
        // Simulating a clean file
        resolve({
          clean: true,
          threats: []
        });
      }, 100);
    });
  };
  
  return scanFile;
};

// File processing middleware to handle tasks like virus scanning
const processUploadedFile = (scanFile) => {
  return async (req, res, next) => {
    // Skip if no file
    if (!req.file && !req.files) {
      return next();
    }
    
    try {
      // Process single file
      if (req.file) {
        const scanResult = await scanFile(req.file.path);
        
        if (!scanResult.clean) {
          // Delete the infected file
          fs.unlinkSync(req.file.path);
          return res.status(400).json({
            error: 'Security threat detected',
            message: 'The uploaded file contains potential security threats and was rejected',
            threats: scanResult.threats
          });
        }
        
        req.file.scanResult = scanResult;
      }
      
      // Process multiple files
      if (req.files) {
        // Handle array of files
        if (Array.isArray(req.files)) {
          for (const file of req.files) {
            const scanResult = await scanFile(file.path);
            
            if (!scanResult.clean) {
              // Delete the infected file
              fs.unlinkSync(file.path);
              return res.status(400).json({
                error: 'Security threat detected',
                message: 'One of the uploaded files contains potential security threats and was rejected',
                filename: file.originalname,
                threats: scanResult.threats
              });
            }
            
            file.scanResult = scanResult;
          }
        }
        // Handle fields of files
        else {
          for (const fieldName of Object.keys(req.files)) {
            for (const file of req.files[fieldName]) {
              const scanResult = await scanFile(file.path);
              
              if (!scanResult.clean) {
                // Delete the infected file
                fs.unlinkSync(file.path);
                return res.status(400).json({
                  error: 'Security threat detected',
                  message: 'One of the uploaded files contains potential security threats and was rejected',
                  filename: file.originalname,
                  fieldName,
                  threats: scanResult.threats
                });
              }
              
              file.scanResult = scanResult;
            }
          }
        }
      }
      
      next();
    } catch (error) {
      console.error('Error processing uploaded file:', error);
      next(error);
    }
  };
};

// Enhanced file schema to support more metadata
const enhancedFileSchema = new mongoose.Schema({
  originalName: { type: String, required: true },
  encoding: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  filename: { type: String, required: true },
  path: { type: String, required: true },
  category: { 
    type: String, 
    enum: ['document', 'image', 'spreadsheet', 'archive', 'medical', 'other', 'unknown'],
    default: 'unknown'
  },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true },
  organizationId: { type: String, required: true },
  fieldName: { type: String }, // Optional field for multiple upload with fields
  securityScan: {
    performed: { type: Boolean, default: false },
    clean: { type: Boolean },
    scanTime: { type: Date },
    threats: [String]
  },
  metadata: {
    pageCount: { type: Number }, // For documents
    dimensions: { // For images
      width: { type: Number },
      height: { type: Number }
    },
    duration: { type: Number }, // For audio/video
    author: { type: String },
    creationDate: { type: Date },
    modificationDate: { type: Date },
    keywords: [String],
    title: { type: String },
    description: { type: String }
  },
  thumbnailPath: { type: String }, // Path to generated thumbnail
  versions: [{ // For tracking revisions
    versionNumber: { type: Number },
    filename: { type: String },
    path: { type: String },
    size: { type: Number },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    uploadedAt: { type: Date }
  }],
  accessCount: { type: Number, default: 0 }, // Track how often the file is accessed
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Update the routes to use our enhanced file upload functionality
const setupFileRoutes = (app) => {
  const uploads = configureFileUpload();
  const scanFile = setupVirusScan();
  
  // Route for single file upload
  app.post(
    '/api/files/upload', 
    authenticate, 
    uploads.single, 
    handleFileUploadErrors,
    processUploadedFile(scanFile),
    handleFileUpload
  );
  
  // Route for multiple file upload
  app.post(
    '/api/files/upload-multiple', 
    authenticate, 
    uploads.multiple, 
    handleFileUploadErrors,
    processUploadedFile(scanFile),
    handleFileUpload
  );
  
  // Route for field-based multiple file upload
  app.post(
    '/api/files/upload-fields', 
    authenticate, 
    uploads.fields, 
    handleFileUploadErrors,
    processUploadedFile(scanFile),
    handleFileUpload
  );
  
  // Setup routes for previewing and downloading files
  setupFilePreviewRoute(app);
  
  // Route to get file metadata
  app.get('/api/files/:fileId/metadata', authenticate, async (req, res) => {
    try {
      const { fileId } = req.params;
      
      const file = await File.findById(fileId);
      
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Check if user has access to this file
      const conversation = await Conversation.findOne({
        _id: file.conversationId,
        participants: req.user._id
      });
      
      if (!conversation) {
        return res.status(403).json({ message: 'Unauthorized' });
      }
      
      // Track access
      file.accessCount += 1;
      await file.save();
      
      // Return file metadata
      res.json({
        id: file._id,
        originalName: file.originalName,
        mimetype: file.mimetype,
        size: file.size,
        category: file.category,
        uploadedBy: file.uploadedBy,
        conversation: file.conversationId,
        createdAt: file.createdAt,
        metadata: file.metadata,
        accessCount: file.accessCount,
        versions: file.versions.map(v => ({
          versionNumber: v.versionNumber,
          uploadedAt: v.uploadedAt,
          size: v.size
        }))
      });
    } catch (error) {
      console.error('Error getting file metadata:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  // Route to replace a file (new version)
  app.post('/api/files/:fileId/replace', authenticate, uploads.single, async (req, res) => {
    try {
      const { fileId } = req.params;
      
      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
      }
      
      const file = await File.findById(fileId);
      
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Check if user has access to this file
      const conversation = await Conversation.findOne({
        _id: file.conversationId,
        participants: req.user._id
      });
      
      if (!conversation) {
        return res.status(403).json({ message: 'Unauthorized' });
      }
      
      // Create a new version entry
      const newVersion = {
        versionNumber: (file.versions.length + 1),
        filename: file.filename,
        path: file.path,
        size: file.size,
        uploadedBy: file.uploadedBy,
        uploadedAt: file.createdAt
      };
      
      // Update the file with new information
      file.versions.push(newVersion);
      file.originalName = req.file.originalname;
      file.encoding = req.file.encoding;
      file.mimetype = req.file.mimetype;
      file.size = req.file.size;
      file.filename = req.file.filename;
      file.path = req.file.path;
      file.uploadedBy = req.user._id;
      file.updatedAt = new Date();
      
      await file.save();
      
      res.json({
        id: file._id,
        originalName: file.originalName,
        mimetype: file.mimetype,
        size: file.size,
        versionNumber: newVersion.versionNumber,
        updatedAt: file.updatedAt
      });
    } catch (error) {
      console.error('Error replacing file:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  // Route to delete a file
  app.delete('/api/files/:fileId', authenticate, async (req, res) => {
    try {
      const { fileId } = req.params;
      
      const file = await File.findById(fileId);
      
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Check if user has access to this file
      const conversation = await Conversation.findOne({
        _id: file.conversationId,
        participants: req.user._id
      });
      
      if (!conversation) {
        return res.status(403).json({ message: 'Unauthorized' });
      }
      
      // Only allow deletion if the user uploaded the file or is an admin
      if (!file.uploadedBy.equals(req.user._id) && req.user.userType !== 'admin') {
        return res.status(403).json({ message: 'You do not have permission to delete this file' });
      }
      
      // Delete the physical file
      fs.unlinkSync(file.path);
      
      // Delete any thumbnails
      if (file.thumbnailPath) {
        try {
          fs.unlinkSync(file.thumbnailPath);
        } catch (err) {
          console.error('Error deleting thumbnail:', err);
        }
      }
      
      // Delete version files
      for (const version of file.versions) {
        try {
          fs.unlinkSync(version.path);
        } catch (err) {
          console.error(`Error deleting version ${version.versionNumber}:`, err);
        }
      }
      
      // Remove from database
      await File.deleteOne({ _id: fileId });
      
      // Log the deletion
      const auditEntry = new AuditLog({
        action: 'FILE_DELETE',
        userId: req.user._id,
        resourceType: 'file',
        resourceId: fileId,
        details: {
          filename: file.originalName,
          mimetype: file.mimetype
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        organizationId: req.organizationId
      });
      
      await auditEntry.save();
      
      res.json({ message: 'File deleted successfully' });
    } catch (error) {
      console.error('Error deleting file:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
};

module.exports = {
  configureFileUpload,
  handleFileUploadErrors,
  processUploadedFile,
  setupFileRoutes,
  enhancedFileSchema,
  allowedMimeTypes
};
  