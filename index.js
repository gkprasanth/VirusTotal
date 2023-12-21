const express = require('express');
const nvt = require('node-virustotal');
const app = express();
const cors = require('cors')
const bodyParser = require('body-parser');
const multer = require('multer');
app.use(bodyParser.json());
app.use(cors())

const API_KEY = '492f79d487cf19d747f84abd57f085660be87db662fcd688e55e2b57f29868b3';

const API_KEY1 = '193b653f993549b075b5c55daa6c700c5a254bf3af01e9c1ba1b79cdb9637226';
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// const vt = nvt.makeAPI(API_KEY);
const request = nvt.makeAPI().setKey(API_KEY1);

app.post('/scan/file', upload.single('fileInput'), (req, res) => {
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    // This line is not needed and should be removed
    console.log('Received file:', file);

    request.fileLookup(file, (err, vtRes) => {
        if (err) {
            console.log('Virustotal API did not work because:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        const road = JSON.parse(vtRes);

        if (road.data.attributes.last_analysis_results.Kaspersky.result !== 'clean') {
            console.log('It is not clean');
        } else {
            console.log('The link is safe');
        }

        // Only send the response once, after all operations are completed
        res.json({ result: road.data.attributes.last_analysis_results.Avira });
    });
});


app.post('/home', (req, res) => {
    const domain = req.body.urlInput;
    request.domainLookup(domain, function (err, vtRes) {
        console.log(domain)
        if (err) {
            console.log('Virustotal API did not work because:');
            console.log(err);
            res.status(500).json({ error: 'Internal Server Error' });
            return;
        }
        var road = JSON.parse(vtRes);

        if (road.data.attributes.last_analysis_results.Kaspersky.result !== "clean") {
            console.log("It is not clean");
        } else {
            console.log("The link is safe");
        }

        // Send the response with the 'road' variable
        res.json(road.data.attributes.last_analysis_results.Avira);
    });
});

app.listen(4000, () => {
    console.log("Server started");
});
