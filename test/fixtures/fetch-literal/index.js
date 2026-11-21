// "https://not-a-call.example.com" is only text here.
const API = "https://api.example.com/v1";
export const call = (id) => fetch(`${API}/items/${id}`);
export const ws = () => new WebSocket("wss://live.example.com/socket");
