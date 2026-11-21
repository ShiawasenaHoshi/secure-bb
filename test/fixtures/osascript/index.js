const { execFile } = require("node:child_process");
module.exports = () => execFile("osascript", ["-e", 'display notification "done"']);
