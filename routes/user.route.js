const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
let path=require("path")
require("dotenv").config();
let userRoute = express.Router();
require("dotenv").config();
const { UserModel } = require("../models/user.model");
let {BlacklistModel}=require("../models/blacklistmodel")
let {auth}=require("../middlewares/authmiddleware");
const { request } = require("http");
const multer = require('multer');
const sharp = require('sharp');

// Set up Multer storage
// const absoluteUploadPath = path.join(__dirname,"..","uploads");
// console.log(absoluteUploadPath)
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, absoluteUploadPath); // Set the destination folder for uploaded files
//   },
//   filename: (req, file, cb) => {
//     // Generate a unique file name (you can use a library like `uuid`)
//     const uniqueFileName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
//     cb(null, uniqueFileName);
//   },
// });
// const upload = multer({ storage });


userRoute.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  let userData = await UserModel.findOne({email});
  if (userData) {
    res.status(400);
    res.send("user already exists");
  } else {
    bcrypt.hash(password, +process.env.saltRounds, async function (err, hash) {
      if (err) {
        console.log(err);
        res.status(400);
        res.send("something went wrong");
      } else {
        let userRegisterData = new UserModel({
          name,
          email,
          password: hash,
          image:"https://pinnacle.works/wp-content/uploads/2022/06/dummy-image.jpg"
        });
        await userRegisterData.save();
        res.send("user registered");
      }
    });
  }
});

userRoute.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let userData = await UserModel.find({ email });
  console.log(userData);
 
  if (userData.length > 0) {
    bcrypt.compare(password, userData[0].password, function (err, result) {
      if (result) {
        //   normal token
        let  accessToken = jwt.sign(
          { name: userData[0].name, userID: userData[0]._id },
          process.env.access,
          { expiresIn:"1h" }
        );

        //   refresh token
        var refreshToken = jwt.sign(
          { name: userData[0].name, userID: userData[0]._id },
          process.env.access,
          { expiresIn:"7d" }
        );
        res.cookie("accesstoken", accessToken, {
          maxAge: 1000 * 60 * 10,
          httpOnly: true,
        });
        res.cookie("refreshToken", refreshToken, {
          maxAge: 1000 * 60 * 10,
          httpOnly: true,
        });
        userData[0].password=undefined
        const userDataQueryParam = encodeURIComponent(JSON.stringify(userData[0]));
         res.status(200).send({msg:"login success full",
        data:userDataQueryParam,
        role:userData[0].role,
        "userinfo":userData[0],
       status:200})
      } else {
        res.status(400);
        res.send({ msg: "wrong credentials",status:400});
      }
    });
  } else {
    res.status(404);
    res.send({ msg: "signup first",status:404});
  }
});

userRoute.post("/logout", async (req, res) => {
  // const token = req.headers.authorization;
  try {
    let {refreshtoken,accesstoken}=req.cookies
    let  blacklistref=new BlacklistModel({token:refreshtoken})
    let blacklistacc=new BlacklistModel({token:accesstoken})
    await blacklistref.save()
    await blacklistacc.save()
    res.send("logout successful");
  } catch (error) {
    res.send(err)
  }
 
});

userRoute.get("/newtoken",auth,async(req,res)=>{
   
  try{
   let{refreshtoken}=req.cookies
   let isblacklited=await BlacklistModel.findOne({token:refreshtoken})
   if(isblacklited){
      res.send("login again..")
   }
   else{
    let isvalid=jwt.verify(refreshtoken,process.env.refresh)
    if(isvalid){
     let newaccesstoken=jwt.sign({"userid":isvalid.userid},process.env.access,{expiresIn:"1hr"})
     
     res.cookie("accesstoken",newaccesstoken,{expiresIn:"1hr"})
     res.send("token genarated")
    }
    else{
      res.send("login again")
    }
  }
  }
  catch(err){
      res.send(err.message)
  }
})



userRoute.post("/otp", async (req, res) => {
  const email = req.body.email;
  try {
    const userData = await userModel.find({ email });
    if (userData.length > 0) {
      let otp = Math.floor(Math.random() * 9000 + 1000);
      // let sub = `OTP for resetting the API ACE Password`;
      // let body = `This is Your OTP - ${otp} for resetting the API ACE password, Keep it confedential.`;
      // sendMail(sub, body, email);
      res.send({
        message: otp,
      });
    } else {
      res.status(400);
      res.send({
        message: "Incorrect E-Mail",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(402);
    res.send("something went wrong while sending otp");
  }
});

userRoute.patch("/reset", async (req, res) => {
  try {
    const payload = req.body;

    const _id = payload.id;
    const password = payload.password;

    const userData = await userModel.find({ _id });

    if (userData.length > 0) {
      const ID = userData[0]._id;
      bcrypt.hash(password, 3, async function (err, hashed) {
        const edited = { password: hashed };
        await userModel.findByIdAndUpdate({ _id: ID }, edited);
        res.status(200).send({
          ok: true,
          message: "Password Re-Set Successfully",
        });
      });
    } else {
      res.status(400);
      res.send({ message: "something went wrong" });
    }
  } catch (error) {
    console.log(error);
    res.status(400);
    res.send("something went wrong while resetting password");
  }
});



userRoute.patch("/addteacher/:id", async (req, res) => {
  try {
    const payload = req.body;
    payload.role=["student","tutor"]
    let{id}=req.params
     await UserModel.findByIdAndUpdate({_id:id},payload)
     res.status(400).send({msg:"request successfull"})
  }
  catch(err){
    res.status(400).send({msg:err.message})
  }
});


userRoute.get("/search", async (req, res) => {
  try {
    
    let { subject } = req.query;
  const data = await UserModel.find({
    $and: [
      { subject: { $regex: subject, $options: "i" } },
      { role: "tutor" },
      { appointed: true }
    ]
  });

  res.status(200).send({msg:data})
  } catch (error) {
    res.status(400).send({msg:error.message})
  }
  
  

});
//  to get all the tutor that admin verified
userRoute.get("/appointedtutor", async (req, res) => {
  // res.setHeader('Content-Type', 'application/json'); 
  let x = { role: "tutor", appointed: true };
  let { id } = req.query;
  if (id) {
    x._id = id;
  }

  try {
    let data = await UserModel.find(x);

    res.status(200).send({ msg: data });
  } catch (error) {
    res.status(400).send({ msg: error.message });
  }
});



userRoute.get("/tutor",async(req,res)=>{
  let x={role:"tutor",appointed:false}
  let {id}=req.query
  if(id){
    x._id=id
  }
 
  try {

    let data=await UserModel.find(x)
    res.status(200).send({msg:data})
    
  } catch (error) {
    res.status(400).send({msg:error.message})
  }
})

userRoute.patch("/tutor/:id",async(req,res)=>{
  let {id}=req.params
  try {
    let data=await UserModel.findByIdAndUpdate({_id:id},req.body)
    res.status(200).send({msg:"changed"})
    
  } catch (error) {
    res.status(400).send({msg:error.message})
  }
})



userRoute.get("/filter", async (req, res) => {
  let  subject = req.query.subject? req.query.subject: [];
if(typeof subject!=="object"){
  subject=[subject]
}
  
  console.log(subject)
  const min = req.query.min || 0;
  const max = req.query.max || Number.MAX_SAFE_INTEGER;

  let sort=req.query.sort
  if(sort=="desc"){
    sort=-1
  }
  else if(sort=="asc"){
    sort=1
  }

  let aggrigationpipeline=[
    {
        $match: {
            $and: [
                { subject: { $in: subject } },
                // { price: { $gte: parseInt(min), $lte: parseInt(max) } }
            ]
        }
    }
   
]
  if(sort){
    aggrigationpipeline.push( {
      $sort: { _id: sort}
  })
  }
  try {
      const filteredData = await UserModel.aggregate(aggrigationpipeline);
      
      
      res.send({msg:filteredData});
  } catch (error) {
      res.status(500).json({ error: 'An error occurred while fetching data.' });
  }
});


//photo upload route
userRoute.patch('/upload/:id', async (req, res) => {
  try {
    const { id } = req.params;
    let {uploadedimage}=req.body
    const userData = await UserModel.findByIdAndUpdate(
      id,
      {  uploadedimage:uploadedimage}
    );
    res.status(200).json({msg:"image uploaded successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred during file upload' });
  }
});

//to show the image in the profile page
userRoute.get('/api/images/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    let data=await UserModel.findOne({_id:userId})
    if(data){
      res.status(200).send({msg:data})
    }
    else{
      res.status(400).send({msg:"user not found"})
    }
    
  } catch (error) {
    res.status(400).send({msg:error.message})
    console.log(error)
  }

});


userRoute.get("/search", async (req, res) => {
  try {
    
    let { subject } = req.query;
  const data = await UserModel.find({
    $and: [
      { subject: { $regex: subject, $options: "i" } },
      { role: "tutor" },
      { appointed: true }
    ]
  });

  res.status(200).send({msg:data})
  } catch (error) {
    res.status(400).send({msg:error.message})
  }
  
  

});







userRoute.get("user/:id",async(req,res)=>{
  let {id}=req.params
  try {
    let data=await UserModel.findOne({_id:id})
    data.password=undefined
        const userDataQueryParam = encodeURIComponent(JSON.stringify(data));
         res.status(200).send({msg:"login success full",
        data:userDataQueryParam,
       status:200})
  } catch (error) {
    res.status(400).send({msg:error.message})
  }
})







module.exports = { userRoute };
