let express=require("express")
let paymentroute=express.Router()
require("dotenv").config()


const Razorpay=require("razorpay")
var instance = new Razorpay({
    key_id: process.env.key_id,
    key_secret: process.env.key_secret,
  });

paymentroute.get("/",(req,res)=>{
  res.send("welcome")
}) 

paymentroute.post("/create/orderId",(req,res)=>{
    console.log("create orderID reqest",req.body)

var options = {
  amount: req.body.amount*100,  // amount in the smallest currency unit
  currency: "INR",
  receipt: "rcp11"
};
instance.orders.create(options, function(err, order) {
  console.log(order);
  res.send({orderId:order.id})
});

})

paymentroute.post("api/payment/verify",(req,res)=>{
    
    let body=req.body.response.razorpay_order_id+"|"+req.body.response.razorpay_payment_id;
    var crypto=require("crypto")
    varexpectedSignature=crypto.createHmac("sha256",process.env.secret_key).update(body.toString).digest("hex");
    console.log("sig received",req.body.response.razorpay_signature)
    console.log('sig generated',expectedSignature);

var response={"signatureIsValid":"false"}
if(expectedSignature===req.body.response.razorpay_signature)
response={"signatureIsValid":"true"}
res.send(response);

})



module.exports={paymentroute}