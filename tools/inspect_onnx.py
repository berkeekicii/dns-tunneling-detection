import onnx, onnxruntime as ort
m = onnx.load("models/iforest.ir9.op19.onnx")
sess = ort.InferenceSession("models/iforest.ir9.op19.onnx", providers=["CPUExecutionProvider"])
print("inputs:", [(i.name, i.shape, i.type) for i in sess.get_inputs()])
print("nodes:", sorted(set(n.op_type for n in m.graph.node)))
