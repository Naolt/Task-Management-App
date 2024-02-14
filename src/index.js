const http = require("http");
const { app } = require("./app");

const PORT = process.env.PORT || 8000;

const server = http.createServer(app);
const io = require("socket.io")(server);

// Set io as a property of the app
app.set("socketio", io);

if (process.env.NODE_ENV !== "test") {
  app_server = server.listen(PORT, () => {
    console.log(`Server is running on 8000 `);
  });
} else {
  app_server = server.listen(() => {
    console.log(`Server is running `);
  });
}

module.exports = app_server;
