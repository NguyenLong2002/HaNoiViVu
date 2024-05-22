const jwt = require("jsonwebtoken");

const middlewareController = {
    // Middleware để xác minh token
    verifyToken: (req, res, next) => {
        const token = req.headers.token;
        if (token) {
            const accessToken = token.split(" ")[1];
            jwt.verify(accessToken, "longdeptrai", (err, user) => {
                if (err) {
                    // Trả về lỗi 401 nếu token không hợp lệ
                    return res.status(401).json({ error: "Unauthorized", message: "Token is not valid" });
                }
                // Gán thông tin người dùng đã được xác thực vào req.user
                req.user = user;
                next();
            });
        } else {
            // Trả về lỗi 401 nếu không có token được cung cấp
            res.status(401).json({ error: "Unauthorized", message: "You're not authenticated" });
        }
    },

    verifyTokenAndAdminAuth: (req, res, next) =>{
        middlewareController.verifyToken(req, res, () =>{
            if(req.user.id == req.params.id || req.user.admin){
                next();
            }else{
                res.status(403).json("You're not allowed to delete other");
            }
        });
    }
};

module.exports = middlewareController;
