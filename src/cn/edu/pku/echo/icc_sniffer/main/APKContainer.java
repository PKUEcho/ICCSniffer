package cn.edu.pku.echo.icc_sniffer.main;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import com.googlecode.d2j.Method;
import com.googlecode.d2j.node.DexMethodNode;
import com.googlecode.d2j.reader.BaseDexFileReader;
import com.googlecode.d2j.reader.MultiDexFileReader;

import cn.edu.pku.echo.icc_sniffer.analysis.AnalysisResult;
import cn.edu.pku.echo.icc_sniffer.analysis.ConstAnalysisResult;
import cn.edu.pku.echo.icc_sniffer.cfg.BasicBlock;
import cn.edu.pku.echo.icc_sniffer.cfg.CFGraph;

public class APKContainer {
	public String apk_path = null;

	public APKContainer(String p) {
		apk_path = p;
	}

	private void executeOneMethod(CFGraph cfg, AnalysisResult l, Map<Method, AnalysisResult> const_args_map) {
//		System.out.println("Block number: " + cfg.getBasicBlocks().size());
		cfg.firstBlock().preResult.initParams(l);
		Queue<BasicBlock> queue = new LinkedList<BasicBlock>();
		queue.addAll(cfg.getBasicBlocks());
		while (!(queue.isEmpty())) {
			BasicBlock bb = queue.poll();
//			System.out.println(bb.insn.size());
			boolean ret = bb.execute(const_args_map);
			if (ret) continue; // No changes of sucResult after executing this block
			for (BasicBlock sucBlock : cfg.getSucBlocks(bb)) {
				if (sucBlock.preResult.covers(bb.sucResult))
					continue;
				sucBlock.preResult.mergeResult(bb.sucResult);
				if (!(queue.contains(sucBlock)))
					queue.add(sucBlock);
			}
		}
	}

	public void execute(int iter_step) {
		System.out.println("###### AppContainer starts executing ######");
		long t1 = System.currentTimeMillis() / 1000;
		Path path = Paths.get(apk_path);
		BaseDexFileReader dfr = null;
		byte[] stream;
		try {
			stream = Files.readAllBytes(path);
			dfr = MultiDexFileReader.open(stream);
		} catch (IOException e) {
			e.printStackTrace();
		}

		int clsNumber = dfr.getClassNames().size();
		System.out.println("App: " + apk_path + ", Class Number: " + clsNumber);
		long t2 = System.currentTimeMillis() / 1000;
		
		System.out.println("Constructing call graphs...");
		Set<DexMethodNode> interestedMethods = CallGraph.findInterestedMethods(dfr, iter_step);
		System.out.println("Call graph Done! Interested method numbers: " + interestedMethods.size());
		long t3 = System.currentTimeMillis() / 1000;
		
		System.out.println("Constructing control flow graphs...");
		Map<Method, AnalysisResult> const_args_map = new HashMap<Method, AnalysisResult>();
		Map<Method, CFGraph> cfg_map = new HashMap<Method, CFGraph>();
		for (final DexMethodNode dmn : interestedMethods) {
			CFGraph cfg = new CFGraph(dmn) {
				@Override
				public BasicBlock getNewBasicBlock(int id) {
					return new BasicBlock(id, dmn.codeNode.totalRegister);
				}
			};
			cfg_map.put(dmn.method, cfg);
		}
		System.out.println("Control flow graphs done!");
		long t4 = System.currentTimeMillis() / 1000;

		for (int i = -1; i < iter_step; ++ i) {
			Map<Method, AnalysisResult> new_const_map = new HashMap<Method, AnalysisResult>();
			for (DexMethodNode dmn : interestedMethods) {
				Method method = dmn.method;
				if (!const_args_map.containsKey(method))
					const_args_map.put(method, new ConstAnalysisResult(dmn.codeNode.totalRegister));
//				System.out.println(dmn.method.getOwner() + "->" + dmn.method.getName());
				if (dmn.method.getName().equals("v") && dmn.method.getOwner().equals("Lcom/tencent/mm/console/b;"))
					ConstConfig.DEBUG = true;
				else
					ConstConfig.DEBUG = false;
				executeOneMethod(cfg_map.get(method), const_args_map.get(method), new_const_map);
			}
			const_args_map = new_const_map;
		}
		long t5 = System.currentTimeMillis() / 1000;

		printConstMap(const_args_map);
		
		System.out.println("Overall: " + (t5 - t1) + "sec, Read: " + (t2 - t1) + ", Call Graph: " + (t3 - t2) +
				", CFG: " + (t4 - t3) + ", Execute: " + (t5 - t4));
	}

	private void printConstMap(Map<Method, AnalysisResult> const_map) {
		Iterator<?> it = const_map.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry pair = (Map.Entry) it.next();
			Method method = (Method) pair.getKey();
			boolean flag = false;
			for (String str : ConstConfig.interested_method) {
				if (str.equals(method.getName()))
					flag = true;
			}
			if (!flag)
				continue;
			System.out.println("");
			System.out.println(method.getOwner() + "->" + method.getName());
			AnalysisResult ll = (AnalysisResult) pair.getValue();
			ll.printResult();
		}
	}
}
