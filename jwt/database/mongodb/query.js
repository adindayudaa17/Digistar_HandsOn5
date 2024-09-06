const mongoose = require('mongoose');
const schema = require('./schema');
const bcrypt = require('bcrypt');

const Users = mongoose.model('User', schema.userSchema, 'users');
const Orders = mongoose.model('Order', schema.orderSchema, 'orders');

async function getUsers() {
    return Users.find();
}

async function createUser(user) {
    // encrypt user password before creating new user
    user.password = await bcrypt.hash(user.password, 10);
    return Users.create(user);
}

async function updateUser(id, user) {
    // If the user object contains a password, hash it before updating
    if (user.password) {
        user.password = await bcrypt.hash(user.password, 10);
    }
    return Users.findByIdAndUpdate(id, user, { new: true });
}

async function deleteUser(id) {
    return Users.findByIdAndDelete(id);
}

async function findByName(name) {
    return Users.find({ name: name });
}

async function findOneByEmail(email) {
    return Users.findOne({ email: email });
}

async function getOrders() {
    return Orders.find();
}

async function createOrder(order) {
    return Orders.create(order);
}

async function updateOrder(id, order) {
    return Orders.findByIdAndUpdate(id, order, { new: true });
}

async function deleteOrder(id) {
    return Orders.findByIdAndDelete(id);
}

async function findByStatus(status) {
    return Orders.find({ status: status });
}

async function findOneByOrderId(orderId) {
    return Orders.findOne({ orderId: orderId });
}


module.exports = {
    getUsers,
    createUser,
    updateUser,
    deleteUser,
    findByName,
    findOneByEmail,
    getOrders,
    createOrder,
    updateOrder,
    deleteOrder,
    findByStatus,
    findOneByOrderId
}