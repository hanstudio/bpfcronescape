; ModuleID = 'pkill.c'
source_filename = "pkill.c"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf"

%struct.syscalls_enter_kill_args = type { i64, i64, i64, i64 }

@kill_example.fmt = private unnamed_addr constant [25 x i8] c"PID %u is being killed!\0A\00", align 1
@_license = global [4 x i8] c"GPL\00", section "license", align 1, !dbg !0
@llvm.used = appending global [2 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32 (%struct.syscalls_enter_kill_args*)* @kill_example to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define i32 @kill_example(%struct.syscalls_enter_kill_args* nocapture readonly) #0 section "tracepoint/syscalls/sys_enter_kill" !dbg !26 {
  %2 = alloca [25 x i8], align 1
  call void @llvm.dbg.value(metadata %struct.syscalls_enter_kill_args* %0, metadata !39, metadata !DIExpression()), !dbg !44
  %3 = getelementptr inbounds %struct.syscalls_enter_kill_args, %struct.syscalls_enter_kill_args* %0, i64 0, i32 3, !dbg !45
  %4 = load i64, i64* %3, align 8, !dbg !45, !tbaa !47
  %5 = icmp eq i64 %4, 9, !dbg !53
  br i1 %5, label %6, label %11, !dbg !54

; <label>:6:                                      ; preds = %1
  %7 = getelementptr inbounds [25 x i8], [25 x i8]* %2, i64 0, i64 0, !dbg !55
  call void @llvm.lifetime.start.p0i8(i64 25, i8* nonnull %7) #3, !dbg !55
  call void @llvm.dbg.declare(metadata [25 x i8]* %2, metadata !40, metadata !DIExpression()), !dbg !56
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %7, i8* getelementptr inbounds ([25 x i8], [25 x i8]* @kill_example.fmt, i64 0, i64 0), i64 25, i32 1, i1 false), !dbg !56
  %8 = getelementptr inbounds %struct.syscalls_enter_kill_args, %struct.syscalls_enter_kill_args* %0, i64 0, i32 2, !dbg !57
  %9 = load i64, i64* %8, align 8, !dbg !57, !tbaa !58
  %10 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %7, i32 25, i64 %9, i64 8) #3, !dbg !59
  call void @llvm.lifetime.end.p0i8(i64 25, i8* nonnull %7) #3, !dbg !60
  br label %11

; <label>:11:                                     ; preds = %1, %6
  ret i32 0, !dbg !60
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #2

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i32, i1) #2

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #2

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.value(metadata, metadata, metadata) #1

attributes #0 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable }
attributes #2 = { argmemonly nounwind }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!22, !23, !24}
!llvm.ident = !{!25}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 17, type: !19, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, globals: !5)
!3 = !DIFile(filename: "pkill.c", directory: "/home/ubuntu/ebpf/bpfcronescape/example")
!4 = !{}
!5 = !{!0, !6}
!6 = !DIGlobalVariableExpression(var: !7, expr: !DIExpression())
!7 = distinct !DIGlobalVariable(name: "bpf_trace_printk", scope: !2, file: !8, line: 170, type: !9, isLocal: true, isDefinition: true)
!8 = !DIFile(filename: "../libbpf/src/root/usr/include/bpf/bpf_helper_defs.h", directory: "/home/ubuntu/ebpf/bpfcronescape/example")
!9 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!10 = !DISubroutineType(types: !11)
!11 = !{!12, !13, !16, null}
!12 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!14 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !15)
!15 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!16 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !17, line: 27, baseType: !18)
!17 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "/home/ubuntu/ebpf/bpfcronescape/example")
!18 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !15, size: 32, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 4)
!22 = !{i32 2, !"Dwarf Version", i32 4}
!23 = !{i32 2, !"Debug Info Version", i32 3}
!24 = !{i32 1, !"wchar_size", i32 4}
!25 = !{!"clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)"}
!26 = distinct !DISubprogram(name: "kill_example", scope: !3, file: !3, line: 11, type: !27, isLocal: false, isDefinition: true, scopeLine: 11, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !38)
!27 = !DISubroutineType(types: !28)
!28 = !{!29, !30}
!29 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "syscalls_enter_kill_args", file: !3, line: 4, size: 256, elements: !32)
!32 = !{!33, !35, !36, !37}
!33 = !DIDerivedType(tag: DW_TAG_member, name: "pad", scope: !31, file: !3, line: 5, baseType: !34, size: 64)
!34 = !DIBasicType(name: "long long int", size: 64, encoding: DW_ATE_signed)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "syscall_nr", scope: !31, file: !3, line: 6, baseType: !12, size: 64, offset: 64)
!36 = !DIDerivedType(tag: DW_TAG_member, name: "pid", scope: !31, file: !3, line: 6, baseType: !12, size: 64, offset: 128)
!37 = !DIDerivedType(tag: DW_TAG_member, name: "sig", scope: !31, file: !3, line: 7, baseType: !12, size: 64, offset: 192)
!38 = !{!39, !40}
!39 = !DILocalVariable(name: "ctx", arg: 1, scope: !26, file: !3, line: 11, type: !30)
!40 = !DILocalVariable(name: "fmt", scope: !26, file: !3, line: 13, type: !41)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !15, size: 200, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 25)
!44 = !DILocation(line: 11, column: 51, scope: !26)
!45 = !DILocation(line: 12, column: 13, scope: !46)
!46 = distinct !DILexicalBlock(scope: !26, file: !3, line: 12, column: 8)
!47 = !{!48, !52, i64 24}
!48 = !{!"syscalls_enter_kill_args", !49, i64 0, !52, i64 8, !52, i64 16, !52, i64 24}
!49 = !{!"long long", !50, i64 0}
!50 = !{!"omnipotent char", !51, i64 0}
!51 = !{!"Simple C/C++ TBAA"}
!52 = !{!"long", !50, i64 0}
!53 = !DILocation(line: 12, column: 17, scope: !46)
!54 = !DILocation(line: 12, column: 8, scope: !26)
!55 = !DILocation(line: 13, column: 5, scope: !26)
!56 = !DILocation(line: 13, column: 10, scope: !26)
!57 = !DILocation(line: 14, column: 45, scope: !26)
!58 = !{!48, !52, i64 16}
!59 = !DILocation(line: 14, column: 5, scope: !26)
!60 = !DILocation(line: 16, column: 1, scope: !26)
