"""
rfeye_server — MVC-organized RFeye IRC server.

  models.py       Node registry, incident log, audio capture buffer.
                   Pure state + mutation logic, no networking.
  views.py         WebSocket broadcast + dashboard HTTP static serving.
                   Presentation only — never parses inbound protocol data.
  controllers.py   UDP/WebSocket protocol handlers. The only layer that
                   knows the wire format; translates messages into model
                   calls and view pushes.
  app.py           Entry point — wires models/views/controllers together
                   and runs the event loop.
"""
