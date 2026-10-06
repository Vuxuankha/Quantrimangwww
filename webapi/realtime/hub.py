from __future__ import annotations
import asyncio, json
from fastapi import WebSocket

class EventHub:
    def __init__(self):
        self.clients:set[WebSocket]=set(); self.loop:asyncio.AbstractEventLoop|None=None
    def bind_loop(self,loop): self.loop=loop
    async def connect(self,ws:WebSocket):
        await ws.accept(); self.clients.add(ws)
    def disconnect(self,ws:WebSocket): self.clients.discard(ws)
    async def broadcast(self,event:dict):
        dead=[]
        for ws in list(self.clients):
            try: await ws.send_text(json.dumps(event,ensure_ascii=False,default=str))
            except Exception: dead.append(ws)
        for ws in dead:self.clients.discard(ws)
    def broadcast_threadsafe(self,event:dict):
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(event),self.loop)

hub=EventHub()
