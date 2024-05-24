const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        email:{
            type:String,
            required:true,
            unique: true, // Đảm bảo email là duy nhất
            match: [/.+\@.+\..+/, 'Please fill a valid email address'], // Xác thực định dạng email
        },
        username:{
            type:String,
            required:true,
            minlength:4,
        },
        password:{
            type:String,
            required:true,
            minlength:6,
        },
        admin:{
            type: Boolean,
            default:false,
        },
        emailVerified: { 
            type: Boolean,
             default: false ,
        },
        resetPasswordToken:{
            type: String,
            default:null,
        },
        resetPasswordExpire:{
            type: String,
            default:null,
        },

    },
    {
        timestamps:true,
        versionKey:false,
    }
);
module.exports =  mongoose.model("User",userSchema);