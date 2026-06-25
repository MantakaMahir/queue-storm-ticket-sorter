from fastapi import FastAPI

from app.schemas import TicketRequest, TicketResponse
from app.classifier import classify_ticket

app = FastAPI(title="QueueStorm Ticket Sorter API")


@app.get("/health")
def health():
    return {"status": "ok", "service": "queue-storm-ticket-sorter"}


@app.post("/sort-ticket", response_model=TicketResponse)
def sort_ticket(payload: TicketRequest):
    result = classify_ticket(
        ticket_id=payload.ticket_id,
        message=payload.message,
    )
    return result
