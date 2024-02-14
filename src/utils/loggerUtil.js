const { createLogger, format, transports } = require("winston");
const { combine, timestamp, printf, splat } = format;

const logFormat = printf(({ level, message, timestamp, ...metadata }) => {
  const details = Object.keys(metadata).length
    ? ` ${JSON.stringify(metadata)}`
    : "";
  return `${timestamp} ${level}:${details} ${message}`;
});

const logger = createLogger({
  format: combine(
    splat(), // Enables capturing additional data
    timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    logFormat
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: "error.log", level: "error" }),
    new transports.File({ filename: "combined.log" }),
  ],
});

module.exports = logger;
