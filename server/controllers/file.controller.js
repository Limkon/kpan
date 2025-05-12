const fs = require('fs').promises; // Using promise-based fs for async/await
const path = require('path');
const { userFilesBasePath } = require('../config/storage.config');
const { mkdirp } = require('mkdirp');

// Helper to get the absolute path for a user's file/folder
const getUserFilePath = (userId, relativePath = '') => {
  const userBaseDir = path.join(userFilesBasePath, String(userId));
  // Sanitize relativePath to prevent path traversal. Resolve it against userBaseDir.
  // path.join itself helps, but further checks are good.
  const absolutePath = path.resolve(userBaseDir, relativePath);

  // Crucial security check: ensure the resolved path is still within the user's base directory
  if (!absolutePath.startsWith(path.resolve(userBaseDir))) {
      throw new Error("Path traversal attempt detected.");
  }
  return absolutePath;
};

exports.listDirectory = async (req, res) => {
  try {
    const userId = req.userId;
    const relativePath = req.query.path || ''; // e.g., "/documents" or "" for root
    const targetPath = getUserFilePath(userId, relativePath);

    await mkdirp(targetPath); // Ensure directory exists

    const items = await fs.readdir(targetPath, { withFileTypes: true });
    const fileDetails = await Promise.all(
      items.map(async (item) => {
        const itemPath = path.join(targetPath, item.name);
        try {
            const stats = await fs.stat(itemPath);
            return {
              name: item.name,
              isDirectory: item.isDirectory(),
              isFile: item.isFile(),
              size: stats.size,
              lastModified: stats.mtime,
              // For frontend, a relative path from user's root is useful
              path: path.join(relativePath, item.name)
            };
        } catch (statError) {
            // Handle cases where stat might fail (e.g. broken symlink)
            console.error(`Could not stat ${itemPath}:`, statError);
            return { name: item.name, error: "Could not retrieve details" };
        }
      })
    );
    res.status(200).send(fileDetails);
  } catch (error) {
    if (error.message.includes("Path traversal attempt")) {
        return res.status(403).send({ message: "Access denied: Invalid path." });
    }
    if (error.code === 'ENOENT') {
        return res.status(404).send({ message: "Directory not found." });
    }
    console.error("Error listing directory:", error);
    res.status(500).send({ message: "Error listing directory contents." });
  }
};

exports.uploadFile = (req, res) => {
  // File upload is handled by multer middleware.
  // It will place files in `server/uploads/<userId>/<path_from_query>`
  if (!req.files || req.files.length === 0) {
    return res.status(400).send({ message: "No files were uploaded." });
  }
  // req.files contains an array of uploaded file objects
  const uploadedFiles = req.files.map(file => ({
    originalName: file.originalname,
    filename: file.filename, // Name on disk (might be same as originalName depending on multer config)
    path: file.path,       // Full path on server
    size: file.size,
    relativePath: path.join(req.query.path || '', file.originalname) // Relative path for client
  }));
  res.status(201).send({ message: "Files uploaded successfully!", files: uploadedFiles });
};

exports.downloadFile = async (req, res) => {
  try {
    const userId = req.userId;
    const relativePath = req.query.path; // e.g., "/documents/myfile.txt"

    if (!relativePath) {
      return res.status(400).send({ message: "File path is required." });
    }
    const filePath = getUserFilePath(userId, relativePath);

    // Check if file exists (fs.access or fs.stat)
    await fs.access(filePath, fs.constants.F_OK);

    res.download(filePath, path.basename(relativePath), (err) => {
      if (err) {
        // Handle errors that occur after headers may have been sent
        // For example, if the file is unreadable or network issues.
        if (!res.headersSent) {
            if (err.code === 'ENOENT') {
                 return res.status(404).send({ message: "File not found for download." });
            }
            console.error("Download error (headers not sent):", err);
            return res.status(500).send({ message: "Could not download file." });
        } else {
            // If headers already sent, the error must be handled differently
            // Often, this means the connection might be closed or an error logged
            console.error("Download stream error (headers sent):", err);
        }
      }
    });
  } catch (error) {
    if (error.message.includes("Path traversal attempt")) {
        return res.status(403).send({ message: "Access denied: Invalid file path." });
    }
    if (error.code === 'ENOENT') { // Error from fs.access if file doesn't exist
        return res.status(404).send({ message: "File not found." });
    }
    console.error("Error preparing file for download:", error);
    res.status(500).send({ message: "Error downloading file." });
  }
};

exports.createFolder = async (req, res) => {
    try {
        const userId = req.userId;
        const relativePath = req.body.path; // e.g., "/new_folder" or "/documents/new_folder"

        if (!relativePath) {
            return res.status(400).send({ message: "Folder path is required." });
        }

        const folderPath = getUserFilePath(userId, relativePath);

        // Check if it already exists
        try {
            const stats = await fs.stat(folderPath);
            if (stats.isDirectory()) {
                return res.status(409).send({ message: "Folder already exists." });
            } else {
                return res.status(409).send({ message: "A file with the same name already exists." });
            }
        } catch (statErr) {
            if (statErr.code !== 'ENOENT') { // If error is not "not found", rethrow
                throw statErr;
            }
            // ENOENT means it doesn't exist, which is good, we can create it
        }

        await mkdirp(folderPath);
        res.status(201).send({ message: "Folder created successfully.", path: relativePath });

    } catch (error) {
        if (error.message.includes("Path traversal attempt")) {
            return res.status(403).send({ message: "Access denied: Invalid folder path." });
        }
        console.error("Error creating folder:", error);
        res.status(500).send({ message: "Error creating folder." });
    }
};

exports.deleteItem = async (req, res) => {
    try {
        const userId = req.userId;
        const relativePath = req.query.path;

        if (!relativePath) {
            return res.status(400).send({ message: "Item path is required for deletion." });
        }
        const itemPath = getUserFilePath(userId, relativePath);

        const stats = await fs.stat(itemPath); // Will throw ENOENT if not found

        if (stats.isDirectory()) {
            await fs.rm(itemPath, { recursive: true, force: true }); // force helps with non-empty dirs
        } else {
            await fs.unlink(itemPath);
        }
        res.status(200).send({ message: `Item '${path.basename(relativePath)}' deleted successfully.` });

    } catch (error) {
        if (error.message.includes("Path traversal attempt")) {
            return res.status(403).send({ message: "Access denied: Invalid item path." });
        }
        if (error.code === 'ENOENT') {
            return res.status(404).send({ message: "Item not found." });
        }
        console.error("Error deleting item:", error);
        res.status(500).send({ message: "Error deleting item." });
    }
};

// Placeholder for rename
exports.renameItem = async (req, res) => {
    // TODO: Implement rename logic
    // Needs oldPath and newPath from req.body
    // Use fs.rename()
    // Ensure newPath doesn't already exist or handle conflicts
    // Validate paths carefully
    res.status(501).send({ message: "Rename not implemented yet." });
};
