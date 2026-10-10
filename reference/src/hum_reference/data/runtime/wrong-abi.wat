(component (core module $m (func (export "decide") (result i32) i32.const 0)) (core instance $i (instantiate $m)) (func (export "decide") (result u32) (canon lift (core func $i "decide"))))
