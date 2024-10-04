const express=require("express")
const jwt=require("jsonwebtoken")
const app=express();

app.use(express.json())

const users=[
    {
        id:"1",
        username:'sintu',
        password:"sintu0989",
        isAdmin:"true"

    },
    {
        id:"2",
        username:'suman',
        password:"suman0989",
        isAdmin:"false"

    }
]

let refreshTokens=[];
app.post("/api/refresh",(req,res)=>{
    //take the refresh token from the user
    const refreshToken=req.body.token;

    //send error if there is no token or its invalid
    if (!refreshToken) return res.status(401).json("you are not authenticated")
        if (!refreshTokens.includes(refreshToken)) {
            return res.status(403).json("refresh token is not valid")
        }

        jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
            err && console.log(err);
            refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
        
            const newAccessToken = generateAccessToken(user);
            const newRefreshToken = generateRefreshToken(user);
        
            refreshTokens.push(newRefreshToken);
        
            res.status(200).json({
              accessToken: newAccessToken,
              refreshToken: newRefreshToken,
            });
          });
        

 //if everything is oke create new access token ,refresh token and send to user
})

const generateAccessToken=(user)=>{
    return jwt.sign(
        { id: user.id, isAdmin: user.isAdmin }, // JWT में यूज़र की जानकारी डालते हैं
        "mysecretkey", // ये हमारा सीक्रेट की है जो टोकन को साइन करता है
        { expiresIn: "20m" } // टोकन की समय सीमा, यहाँ पर 20 सेकंड है
    );
}
const generateRefreshToken=(user)=>{
   return jwt.sign(
       { id: user.id, isAdmin: user.isAdmin }, // JWT में यूज़र की जानकारी डालते हैं
       "myRefreshsecretkey", // ये हमारा सीक्रेट की है जो टोकन को साइन करता है
       
   );
}


app.post('/api/login', (req, res) => {
    const { username, password } = req.body; // यूज़र से username और password ले रहे हैं
    const user = users.find((u) => {
        return u.username === username && u.password === password;
    });
    
    if (user) { // अगर यूज़र का username और password सही है
     const accessToken=  generateAccessToken(user);
      const refreshToken=  generateRefreshToken(user);
      refreshTokens.push(refreshToken);
        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken
        });
    } else {
        res.status(400).json("Username or password incorrect!"); // अगर username या password गलत है
    }
});


const verify = (req, res, next) => {
    const authHeader = req.headers.authorization; // Authorization हेडर से टोकन लेते हैं

    if (authHeader) { 
        const token = authHeader.split(" ")[1]; // टोकन को हेडर से निकालते हैं

        jwt.verify(token, "mysecretkey", (err, user) => { // टोकन को verify करते हैं
            if (err) {
                return res.status(403).json("Token is invalid"); // अगर टोकन invalid है
            }
            req.user = user; // वैलिड होने पर यूज़र को req.user में सेट कर देते हैं
            next(); // अगले मिडलवेयर या रूट हैंडलर को कॉल करते हैं
        });
    } else {
        res.status(401).json("You are not authenticated"); // अगर टोकन नहीं मिला
    }
};

app.delete("/api/users/:userId",verify,(req,res)=>{
    if (req.user.id === req.params.userId || req.user.isAdmin) {
        res.status(200).json("user has been deleted")
    }else{
        res.status(403).json("you are not allow to delete this user!")
    }
});

app.post("/api/logout", verify, (req, res) => {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.status(200).json("You logged out successfully.");
  });
  

const PORT=5004;
app.listen(PORT,()=>{
    console.log('server is running!')
})
