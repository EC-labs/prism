from pysentimiento import create_analyzer

emotion_analyzer = create_analyzer(task="emotion", lang="en")
print("Model created")
