package cn.edu.pku.echo.icc_sniffer.analysis;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.googlecode.d2j.DexConstants;
import com.googlecode.d2j.node.DexClassNode;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.reader.DexFileReader;
import com.googlecode.d2j.visitors.DexClassVisitor;
import com.googlecode.d2j.visitors.DexFileVisitor;

public class DexContainer extends DexFileNode implements DexConstants {
	public static Set<String> appClassNames;
	private static HashSet<String> updatedClass;
	public static Set<String> filtedClass;
	// private String outputDexPath;
	// private String apkPath;
	private String appName;
	private boolean needLib;
	private boolean removeRelacted;
	private String dexPath;
	
	private DexContainer(InputStream in, boolean b) {
		removeRelacted = b;
		addDexFile(in);
	}

	public DexContainer(InputStream in, String dexPath) {
		addDexFile(in);
		this.dexPath = dexPath;
		removeRelacted = false;
	}

	private void addDexFile(InputStream in) {
		if (in == null)
			return;
		int count = 0;
		try {
			DexFileNode dfn = new DexFileNode();
			DexFileReader dfr;
			dfr = new DexFileReader(in);
			dfr.accept(dfn);
			for (DexClassNode cn : dfn.clzs) {
				if (!removeRelacted)
					clzs.add(cn);
				else {
					count++;
				}
			}
			System.out
					.println("[DexContainer] remove reflacted activitor! count:"
							+ count);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public DexClassNode getDexClass(String name) {
		for (DexClassNode dcn : clzs) {
			if (dcn.className.equals(name))
				return dcn;
		}
		return null;
	}

	public void freeAll() {
		clzs.clear();
		System.gc();
	}

	public void removeRelactedActivitor() {
		removeRelacted = true;
	}
}
