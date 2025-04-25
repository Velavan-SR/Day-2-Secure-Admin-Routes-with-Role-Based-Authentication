const { JsonWebTokenError } = require("jsonwebtoken");
const jwt = require('jsonwebtoken')

// Middleware to verify if the user is authenticated
const verifyToken = (req, res, next) => {
    // Issue: No JWT verification here yet
    const token = req.cookies.token;
    if(!token){
      return res.status(401).send({message : "un-authorized"})
    }
    const decoded = jwt.verify(token,process.env.JWT_SECRET)
    if (decoded){
      req.role = decoded.role
      next()
    }else{
      return res.status(401).send({message : "Un-authorized"})
    }
  };
  
  // Middleware to verify if the user is an admin
  const isAdmin = (req, res, next) => {
    const role = req.role
    if(!role || role!="admin"){
      return res.status(401).send({message : "Un-autorized"})
    }

    if(role && role=='admin'){
      next();
    } 
  };
  
  module.exports = { verifyToken, isAdmin };