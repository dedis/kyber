//go:build experimental
// +build experimental

package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"
)

type Set struct {
	m map[string]struct{}
}

var Analyzer = &analysis.Analyzer{
	Name: "funcCallTypes",
	Doc:  "prints the types of the function calls",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	var funcs = &Set{m: make(map[string]struct{})}
	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			if fd, ok := node.(*ast.FuncDecl); ok {
				if fd.Type.Params != nil {
					for _, param := range fd.Type.Params.List {
						if t := pass.TypesInfo.TypeOf(param.Type); t != nil {
							if ptr, ok := t.(*types.Pointer); ok {
								if named, ok := ptr.Elem().(*types.Named); ok {
									if named.Obj().Pkg() != nil &&
										named.Obj().Pkg().Path() == "math/big" &&
										named.Obj().Name() == "Int" {
										funcs.m[fd.Name.Name] = struct{}{}
									}
								}
							}
						}
					}
				}
			}
			return true
		})
		for f := range funcs.m {
			fmt.Println(f)
		}
		//ast.Inspect(file, func(node ast.Node) bool {
		//	if call, ok := node.(*ast.CallExpr); ok {
		//		if t := pass.TypesInfo.TypeOf(call.Fun); t != nil {
		//			fmt.Printf("Function call type: %v\n", t)
		//		}
		//	}
		//	return true
		//})
	}
	return nil, nil
}

func main() {
	// Run the analyzer
	singlechecker.Main(Analyzer)

}
