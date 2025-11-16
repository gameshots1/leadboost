const express = require("express");
const path = require("path");
const multer = require("multer");
const XLSX = require("xlsx");

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => res.render("login"));
app.post("/login", (req, res) => res.redirect("/dashboard"));
app.get("/dashboard", (req, res) => res.render("dashboard"));

const upload = multer({ dest: "uploads/" });
app.post("/upload", upload.single("sheet"), (req, res) => {
    if (!req.file) return res.send("No file uploaded.");
    const wb = XLSX.readFile(req.file.path);
    const ws = wb.Sheets[wb.SheetNames[0]];
    const data = XLSX.utils.sheet_to_json(ws);
    res.render("upload", { rows: data });
});

app.listen(3000, () => console.log("LeadBoost running"));
