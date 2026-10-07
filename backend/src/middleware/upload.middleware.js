import multer from "multer";

import path from "path";

import fs from "fs";

/*
|--------------------------------------------------------------------------
| Upload Folder
|--------------------------------------------------------------------------
*/

const uploadDir = "src/uploads";

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, {
    recursive: true,
  });
}

/*
|--------------------------------------------------------------------------
| Storage
|--------------------------------------------------------------------------
*/

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },

  filename: (req, file, cb) => {
    const uniqueName =
      Date.now() +
      "-" +
      Math.round(Math.random() * 1e9) +
      path.extname(file.originalname);

    cb(null, uniqueName);
  },
});

/*
|--------------------------------------------------------------------------
| File Filter
|--------------------------------------------------------------------------
*/

const fileFilter = (req, file, cb) => {
  const ext = path.extname(
    file.originalname
  ).toLowerCase();

  if (ext !== ".exe") {
    return cb(
      new Error(
        "Only .exe files allowed"
      ),
      false
    );
  }

  cb(null, true);
};

/*
|--------------------------------------------------------------------------
| Upload
|--------------------------------------------------------------------------
*/

export const upload = multer({
  storage,

  fileFilter,

  limits: {
    fileSize: 20 * 1024 * 1024,
  },
});