require('dotenv').config();
const mongodb = require('./database/mongodb/db');
const userQuery = require('./database/mongodb/query'); 

mongodb.connectDB();

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { initializePassport, authenticatePassportJwt } = require('./middlewares/passport-jwt');

// Initialize Express app
const app = express();
const PORT = 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Initialize Passport
app.use(initializePassport());

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Route to GET all users - returns the users array as JSON
app.get('/users', authenticatePassportJwt(), (req, res) => {
  userQuery.getUsers().then((users) => {
    res.json(users);
  });
});

// Route to POST a new user - adds a new user to the users array
app.post('/users', authenticatePassportJwt(), (req, res) => {
  const user = req.body;
  userQuery.createUser(user).then((user) => {
    res.status(201).json(user);
  });
});

// Route to PUT (update) a user by id
app.put('/users/:id', authenticatePassportJwt(), (req, res) => {
  const { id } = req.params;
  const user = req.body;
  userQuery.updateUser(id, user).then((user) => {
    res.status(200).json(user);
  });
});

// Route to DELETE a user by id
app.delete('/users/:id', authenticatePassportJwt(), (req, res) => {
  const { id } = req.params;
  userQuery.deleteUser(id).then(() => {
    res.status(204).send();
  });
});

// Route to search users by name
app.get('/users/search', authenticatePassportJwt(), (req, res) => {
  const { name } = req.query;
  if (!name) {
    return res.status(400).send({ message: "Name query parameter is required" });
  }
  userQuery.findByName(name).then((users) => {
    res.status(200).json(users);
  });
});

// Route to login user and generate JWT token
app.post("/user/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const payload = { email, password };
    const token = await login(payload);
    res.status(200).json({ message: "Success login!", token });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

async function login(payload) {
  try {
    const checkUser = await userQuery.findOneByEmail(payload.email);
    console.log(checkUser);
    if (!checkUser) {
      throw new Error('Invalid email or password');
    }
    const isValidPassword = bcrypt.compareSync(payload.password, checkUser.password);
    if (!isValidPassword) {
      throw new Error('Invalid email or password');
    }
    const key = process.env.JWT_SECRET || 'default_secret_key';
    const token = jwt.sign({ email: checkUser.email }, key, { expiresIn: '30m' });
    return token;
  } catch (error) {
    console.error('Error login: ', error);
    throw error;
  }
}

// Route to GET all orders - returns the orders array as JSON
app.get('/orders', authenticatePassportJwt(), (req, res) => {
  userQuery.getOrders().then((orders) => {
    res.json(orders);
  });
});

// Route to POST a new order - adds a new order to the orders array
app.post('/orders', authenticatePassportJwt(), (req, res) => {
  const order = req.body;
  userQuery.createOrder(order).then((order) => {
    res.status(201).json(order);
  });
});

// Route to PUT (update) an order by id
app.put('/orders/:id', authenticatePassportJwt(), (req, res) => {
  const { id } = req.params;
  const order = req.body;
  userQuery.updateOrder(id, order).then((order) => {
    res.status(200).json(order);
  });
});

// Route to DELETE an order by id
app.delete('/orders/:id', authenticatePassportJwt(), (req, res) => {
  const { id } = req.params;
  userQuery.deleteOrder(id).then(() => {
    res.status(204).send();
  });
});

// Route to search orders by status
app.get('/orders/search', authenticatePassportJwt(), (req, res) => {
  const { status } = req.query;
  if (!status) {
    return res.status(400).send({ message: "Status query parameter is required" });
  }
  userQuery.findByStatus(status).then((orders) => {
    res.status(200).json(orders);
  });
});

// Route to find an order by orderId
app.get('/orders/:orderId', authenticatePassportJwt(), (req, res) => {
  const { orderId } = req.params;
  userQuery.findOneByOrderId(orderId).then((order) => {
    res.status(200).json(order);
  });
});
