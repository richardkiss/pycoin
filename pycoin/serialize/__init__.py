import io


def stream_to_bytes(stream_f):
    f = io.BytesIO()
    stream_f(f)
    return f.getvalue()
