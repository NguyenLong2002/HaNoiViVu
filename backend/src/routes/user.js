const router = require("express").Router();
const userController = require("../controllers/userController");
const middlewareController = require("../controllers/middlewareController");

//get all user
router.get('/', middlewareController.verifyToken, userController.getAllUsers),
// router.get('/', userController.getAllUsers),
//get user by id

//delete user
router.delete("/:id", middlewareController.verifyTokenAndAdminAuth,userController.deleteUser),

module.exports = router;