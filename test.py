import speech_recognition as sr

filename = "/home/paul/Downloads/5252144179736.wav"

r = sr.Recognizer()

with sr.AudioFile(filename) as source:
    audio_data = r.record(source)
    text = r.recognize_vosk(audio_data)
    print(text)
