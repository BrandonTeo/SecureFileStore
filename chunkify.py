import math

def chunkify(value, t):
    length = len(value)
    numChunks = 1
    if length < t:
        return [value]
    while length * 1.0 / numChunks > t:
        numChunks = numChunks * 2
    # We need to make sure each chunk is smaller than the threshold we set
    chunk_size = math.ceil(length * 1.0 / numChunks)
    start = 0
    end = chunk_size
    chunk_list = []
    while True:
        chunk_list.append(value[start:end])
        start += chunk_size
        end += chunk_size
        if end > length:
            chunk_list.append(value[start:])
            break
    return chunk_list

a = "Thisissomerandomtext"

c = 5

print(chunkify(a,c))