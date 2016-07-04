package cn.edu.pku.echo.icc_sniffer.main;

import com.googlecode.d2j.node.DexClassNode;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.node.DexMethodNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.reader.BaseDexFileReader;
import com.googlecode.d2j.reader.MultiDexFileReader;

import cn.edu.pku.echo.icc_sniffer.analysis.BasicBlock;
import cn.edu.pku.echo.icc_sniffer.analysis.CFGraph;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {
	public static void main(String[] args) {
		System.out.println("###### Icc-Sniffer starts ######");
		String apk_file = "com.tencent.mobileqq.apk";
		
		Path apk_path = Paths.get(apk_file);
		byte[] stream;
		try {
			stream = Files.readAllBytes(apk_path);
			BaseDexFileReader dfr = MultiDexFileReader.open(stream);
			int clsNumber = dfr.getClassNames().size();
			System.out.println("Class Number: " + clsNumber);
			
			DexFileNode dfn = new DexFileNode();
			dfr.accept(dfn);
//			for (DexClassNode cn : dfn.clzs) {
//				System.out.println(cn.className);
//			}
			DexClassNode dcn = dfn.clzs.get(0);
			DexMethodNode dmn = dcn.methods.get(1);
			System.out.println(dcn.className);
			for (DexStmtNode dsn : dmn.codeNode.stmts)
				System.out.println(dsn.op);
			CFGraph cfg = null;
			if (dmn.codeNode != null) {
				cfg = new CFGraph(dmn){
					@Override
					public BasicBlock getNewBasicBlock(int id) {
						return new BasicBlock(id);
					}
				};
			}
			cfg.printCFG();
//			for (int i = 0; i < clsNumber; ++ i) {
//				System.out.println("Class : " + dxr.getClassNames().get(i));
//			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
