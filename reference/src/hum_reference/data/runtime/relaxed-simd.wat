(component
 (core module $m
   (memory (export "memory") 1)

   (func (export "decide") (result i32) v128.const i32x4 0 0 0 0 v128.const i32x4 0 0 0 0 i8x16.relaxed_swizzle drop i32.const 0))
 (core instance $i (instantiate $m))
 (type $decision (record (field "attributes" (list (tuple string u64))) (field "dedup-keys" (list (list u8)))))
 (type $rejection (record (field "code" u16) (field "retry" bool)))
 (export $d "decision" (type $decision))
 (export $r "rejection" (type $rejection))
 (type $result (result $d (error $r)))
 (func (export "decide") (result $result) (canon lift (core func $i "decide") (memory $i "memory"))))
