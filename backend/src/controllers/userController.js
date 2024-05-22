const User = require("../models/User");

const userController = {
    //get all users
    getAllUsers : async(req, res) =>{
        try{
                const user = await User.find();
                res.status(200).json(user);
        } catch(err){
            res.status(500).json(err);
        };
    },
    //get user by id
    // getUser : async(req,res)=>{
    //     try{
    //         const user = await User.findById(req.params.id);
    //         res.status(200).json(user);
    //     } catch(err){
    //         res.status(500).json(err)
    //     };
    // }
    //delete user
    deleteUser: async(req,res)=>{
        try{
            const user = await User.findById(req.params.id);
            res.status(200).json("Xoa nguoi dung thanh cong!");
        } catch(err){
            res.status(500).json(err)
        };
    },
}

module.exports = userController;