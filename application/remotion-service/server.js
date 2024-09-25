import express from 'express';
import pkg from '@remotion/renderer';
const { getSilentParts } = pkg;
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const upload = multer({ dest: 'uploads/' });

app.post('/get-audible-parts', upload.single('video'), async (req, res) => {
  console.log('Received request to get audible parts');

  try {
    const inputPath = path.join(__dirname, req.file.path);
    console.log(`Input video path: ${inputPath}`);

    console.log('Analyzing video for silent parts...');
    const silentPartsResult = await getSilentParts({
      src: inputPath,
      threshold: -40, // Silence threshold in dB
      minDurationInSeconds: 0.5, // Minimum duration to consider as silence
    });
    console.log('Raw result from getSilentParts:', JSON.stringify(silentPartsResult, null, 2));

    let silentParts = silentPartsResult.silentParts || [];
    console.log('Silent parts:', silentParts);
    console.log(`Found ${silentParts.length} silent parts`);

    // Calculate audible parts
    let audibleParts = [];
    let lastEnd = 0;

    silentParts.forEach(part => {
      if (lastEnd < part.startInSeconds) {
        audibleParts.push({ start: lastEnd, end: part.startInSeconds });
      }
      lastEnd = part.endInSeconds;
    });

    // If there's audio after the last silent part
    if (lastEnd < silentPartsResult.durationInSeconds) {
      audibleParts.push({ start: lastEnd, end: silentPartsResult.durationInSeconds });
    }

    console.log('Audible parts:', audibleParts);
    
    // Send the audible parts data
    res.json(audibleParts);

    // Clean up the temporary file
    await fs.unlink(inputPath);
    console.log('Temporary file cleaned up');

  } catch (error) {
    console.error('Error processing video:', error);
    res.status(500).json({ error: 'Failed to process video', details: error.toString() });

    // Clean up input file in case of error
    try {
      await fs.unlink(req.file.path);
      console.log('Input file cleaned up after error');
    } catch (unlinkError) {
      console.error('Failed to delete input file:', unlinkError);
    }
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Remotion service running on port ${port}`);
});
