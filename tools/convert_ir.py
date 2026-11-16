import sys, os
import onnx
from onnx import version_converter, shape_inference

# Kullanım:
#   python tools/convert_ir.py IN.onnx OUT.onnx [TARGET_OPSET]
# Örn:
#   python tools/convert_ir.py models/iforest.onnx models/iforest.ir9.op13.onnx 13

def info(m):
    ir = m.ir_version
    ops = [(i.domain or "ai.onnx", i.version) for i in m.opset_import]
    return ir, ops

def ensure_tensor_shape(vi):
    """Type=tensor ama shape boş/eksikse en az 1 belirsiz boyut ekle."""
    t = vi.type
    if not t.HasField("tensor_type"):
        return
    tt = t.tensor_type
    # shape alanı yoksa ya da var ama boyut listesi boşsa doldur
    if (not tt.HasField("shape")) or (len(tt.shape.dim) == 0):
        tt.shape.dim.add().dim_param = "unk"

def fix_missing_shapes(m):
    g = m.graph
    for vi in list(g.input) + list(g.value_info) + list(g.output):
        ensure_tensor_shape(vi)
    return m

def main():
    if len(sys.argv) < 3:
        print("usage: python tools/convert_ir.py <in.onnx> <out.onnx> [target_opset]")
        sys.exit(1)

    in_path  = sys.argv[1]
    out_path = sys.argv[2]
    target_opset = int(sys.argv[3]) if len(sys.argv) > 3 else None

    if not os.path.exists(in_path):
        print(f"[err] input not found: {in_path}")
        sys.exit(2)

    m = onnx.load(in_path)
    ir0, ops0 = info(m)
    print(f"[before] IR={ir0} | opsets={ops0}")

    # (Opsiyonel) önce opset düşürmek genelde daha güvenli
    if target_opset is not None:
        try:
            m = version_converter.convert_version(m, target_opset)
        except Exception as e:
            print(f"[warn] opset convert failed: {e} (devam ediliyor)")

    # IR sürümünü 9 yap
    m.ir_version = 9

    # Şekilleri türetmeyi dene; sonra eksikleri yamala
    try:
        m = shape_inference.infer_shapes(m)
    except Exception as e:
        print(f"[warn] shape inference failed: {e}")
    m = fix_missing_shapes(m)

    # Doğrula + kaydet
    onnx.checker.check_model(m)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    onnx.save(m, out_path)

    m2 = onnx.load(out_path)
    ir1, ops1 = info(m2)
    print(f"[after ] IR={ir1} | opsets={ops1}")
    print(f"[ok] saved -> {out_path}")

    # İsteğe bağlı: ORT ile açılabiliyor mu?
    try:
        import onnxruntime as ort
        _ = ort.InferenceSession(out_path, providers=["CPUExecutionProvider"])
        print("[ort] session created successfully.")
    except Exception as e:
        print(f"[ort] note: {e}")

if __name__ == "__main__":
    main()
