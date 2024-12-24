const express = require("express");
const bodyParser = require("body-parser")
const ejs = require ("ejs")
require('dotenv').config()

const mongoose = require ("mongoose")
var encrypt = require('mongoose-encryption');

const app = express()
app.use(express.static("public"))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({extended:true}))

mongoose.connect("mongodb+srv://"+process.env.DB_USER+":"+process.env.DB_PASSWORD+"@"+process.env.DB_TAIL); // SQL: Create DB

const userSchema = new mongoose.Schema({
    email: String,
    password: String
 }); 


userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});


const User = new mongoose.model("User", userSchema); // สร้าง


app.get("/register", (req,res)=> {
    res.render("register");
 })

 app.post("/register", async (req, res) => {
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });

    try {
        await newUser.save();
        res.render("secrets");
    } catch (err) {
        // Handle any errors that occurred during database operation
        console.error('Error during user registration:', err);
        res.status(500).send("Internal server error.");
    }
});


 app.get("/login", (req,res)=> {
    res.render("login");
 })

 app.post("/login", async (req, res)=>{

    const username = req.body.username;
    const password = req.body.password;

try {

    const foundUser = await User.findOne({email: username})

    if (foundUser) { // มี User นั้นจริง
        if (foundUser.password === password) { // ถ้า password ตรง
            res.render("secrets")
        }
        else res.send("Incorrect Password") // ถ้า password ผิด
    }
    else res.send("No user found with that email.")

}
catch (err) {
    console.error('Error during user search:', err)
    res.status(500).send("Internal Server error")
}

   
});




 app.get("/secrets", (req,res)=> {
    res.render("secrets");
 })
 app.get("/", (req,res)=> {
    res.render("home");
 });

 app.get("/logout", (req,res)=>{
   
    res.redirect("/")
})

 
app.listen (3000, () => {
    console.log("Server opened on port 3000")
})
