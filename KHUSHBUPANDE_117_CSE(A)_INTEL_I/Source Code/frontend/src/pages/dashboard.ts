const ws = new WebSocket("ws://localhost:8000/ws");

ws.onmessage = (event) => {
    const alert = JSON.parse(event.data);

    const div = document.createElement("div");
    div.style.border = "2px solid red";
    div.style.padding = "10px";
    div.style.margin = "5px";

    div.innerHTML = `
        <h3>${alert.level} (${alert.risk_score}%)</h3>
        <p>ID: ${alert.person_id}</p>
        <p>${alert.reasons.join(", ")}</p>
    `;

    document.body.prepend(div);
};