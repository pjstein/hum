(component
 (core module $m
   (memory (export "memory") 1)

   (func (export "decide") (result i32) i32.const 0 i32.const 1 i32.store i32.const 4 i32.const 1024 memory.grow i32.const -1 i32.ne i32.store16 i32.const 0))
 (core instance $i (instantiate $m))
 (type $decision (record (field "attributes" (list (tuple string u64))) (field "dedup-keys" (list (list u8)))))
 (type $rejection (record (field "code" u16) (field "retry" bool)))
 (export $d "decision" (type $decision))
 (export $r "rejection" (type $rejection))
 (type $result (result $d (error $r)))
 (func (export "decide") (result $result) (canon lift (core func $i "decide") (memory $i "memory"))))
