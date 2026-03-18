import React, { useState, useEffect } from 'react';
import { 
  Lock, Unlock, Shield, Key, Plus, Copy, Eye, EyeOff, 
  Trash2, Search, Check, AlertTriangle, RefreshCw, X, Save,
  Cloud, LogOut, User, Loader2, Fingerprint, Download, Upload
} from 'lucide-react';

// --- FIREBASE SETUP ---
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithPopup, GoogleAuthProvider, onAuthStateChanged, signOut } from 'firebase/auth';
import { getFirestore, doc, setDoc, onSnapshot } from 'firebase/firestore';

// Cấu hình Firebase
const firebaseConfig = {
  apiKey: "AIzaSyCa-bC8UrfSX_Ir0_2vXTAlBS10Hzr7RDI",
  authDomain: "quanlymatkhau.firebaseapp.com",
  projectId: "quanlymatkhau",
  storageBucket: "quanlymatkhau.firebasestorage.app",
  messagingSenderId: "144750647329",
  appId: "1:144750647329:web:fd6dbe1ca10b652f21eb60"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Hàm lấy đường dẫn lưu trên Firebase
const getVaultDocRef = (userId) => {
  return doc(db, 'users', userId, 'secure_vault', 'encrypted_blob');
};

// --- HÀM HỖ TRỢ CHUYỂN ĐỔI BASE64 VÀ ARRAYBUFFER ---
const buf2b64 = (buf) => btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
const b642buf = (b64) => {
  const binary_string = atob(b64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
};

// --- CÁC HÀM BẢO MẬT (WEB CRYPTO API) ---
const ITERATIONS = 100000;

const getPasswordKey = (password) => {
  return window.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
};

const deriveKey = async (passwordKey, salt) => {
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: ITERATIONS, hash: "SHA-256" },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
};

const encryptData = async (data, key) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedData = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encodedData
  );
  return { ciphertext, iv };
};

const decryptData = async (ciphertext, iv, key) => {
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    ciphertext
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
};

// --- COMPONENT CHÍNH ---
export default function App() {
  const [user, setUser] = useState(null);
  const [appState, setAppState] = useState('CHECKING_AUTH'); // CHECKING_AUTH, LOGIN, CHECKING_DATA, SETUP, UNLOCK, READY
  
  const [masterKey, setMasterKey] = useState(null);
  const [vaultSalt, setVaultSalt] = useState(null);
  const [vault, setVault] = useState([]);
  const [encryptedCloudData, setEncryptedCloudData] = useState(null);
  
  const [masterPasswordInput, setMasterPasswordInput] = useState('');
  const [confirmPasswordInput, setConfirmPasswordInput] = useState('');
  const [authError, setAuthError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingItem, setEditingItem] = useState(null);
  const [toastMessage, setToastMessage] = useState(null);
  const [isSyncing, setIsSyncing] = useState(false);

  // --- TRẠNG THÁI SINH TRẮC HỌC (FACE ID / VÂN TAY) ---
  const [isBiometricSupported, setIsBiometricSupported] = useState(false);
  const [hasBiometricSaved, setHasBiometricSaved] = useState(!!localStorage.getItem('sv_biometric_pwd'));

  useEffect(() => {
    // Kiểm tra xem thiết bị hiện tại có hỗ trợ nhận diện khuôn mặt/vân tay không
    if (window.PublicKeyCredential) {
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then(available => setIsBiometricSupported(available));
    }
  }, []);

  const enableBiometric = async () => {
    try {
      const challenge = window.crypto.getRandomValues(new Uint8Array(32));
      const userId = window.crypto.getRandomValues(new Uint8Array(16));
      const publicKey = {
        challenge: challenge,
        rp: { name: "SecureVault", id: window.location.hostname },
        user: { id: userId, name: user.email, displayName: user.email },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
        timeout: 60000,
      };
      
      // Gọi màn hình quét khuôn mặt/vân tay của điện thoại
      await navigator.credentials.create({ publicKey });
      
      // Nếu quét thành công, lưu mật khẩu vào LocalStorage (Được bảo vệ bởi lớp Sinh trắc học)
      localStorage.setItem('sv_biometric_pwd', masterPasswordInput);
      setHasBiometricSaved(true);
      showToast("Đã thiết lập Face ID/Vân tay thành công!");
    } catch (err) {
      showToast("Hủy thao tác hoặc thiết bị không hỗ trợ.");
    }
  };

  const handleBiometricUnlock = async () => {
    try {
      setAuthError('');
      const challenge = window.crypto.getRandomValues(new Uint8Array(32));
      const publicKey = {
        challenge: challenge,
        rpId: window.location.hostname,
        userVerification: "required",
      };
      
      // Gọi màn hình quét khuôn mặt/vân tay để xác thực
      await navigator.credentials.get({ publicKey });
      
      // Nếu đúng khuôn mặt, lấy mật khẩu chính đã lưu để giải mã
      const savedPwd = localStorage.getItem('sv_biometric_pwd');
      if (savedPwd) {
        await processUnlock(savedPwd);
      } else {
        setAuthError("Không tìm thấy dữ liệu sinh trắc học. Vui lòng nhập mật khẩu.");
      }
    } catch (err) {
      setAuthError("Xác thực khuôn mặt/vân tay thất bại.");
    }
  };

  // Hàm xử lý giải mã được tách ra để tái sử dụng
  const processUnlock = async (password) => {
    if (!encryptedCloudData) throw new Error("No data");
    const salt = b642buf(encryptedCloudData.salt);
    const iv = b642buf(encryptedCloudData.iv);
    const ciphertext = b642buf(encryptedCloudData.data);
    
    const pwdKey = await getPasswordKey(password);
    const key = await deriveKey(pwdKey, salt);
    
    const decryptedVault = await decryptData(ciphertext, iv, key);
    
    setVaultSalt(salt);
    setMasterKey(key);
    setVault(decryptedVault);
    setAppState('READY');
    setMasterPasswordInput(password); // Giữ lại password để có thể thiết lập Sinh trắc học
    showToast("Đã mở khóa!");
  };

  // 1. Lắng nghe trạng thái đăng nhập Firebase
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      if (currentUser) {
        setUser(currentUser);
        setAppState('CHECKING_DATA');
      } else {
        setUser(null);
        setAppState('LOGIN');
      }
    });
    return () => unsubscribe();
  }, []);

  // 2. Lắng nghe dữ liệu từ Firestore khi đã đăng nhập
  useEffect(() => {
    if (!user || appState === 'LOGIN' || appState === 'CHECKING_AUTH') return;

    const docRef = getVaultDocRef(user.uid);
    const unsubscribe = onSnapshot(docRef, (docSnap) => {
      if (docSnap.exists()) {
        const data = docSnap.data();
        setEncryptedCloudData(data);
        setAppState(prev => (prev === 'CHECKING_DATA' || prev === 'READY' ? 'UNLOCK' : prev));
      } else {
        setAppState('SETUP');
      }
    }, (error) => {
      showToast("Lỗi kết nối máy chủ dữ liệu! Hãy kiểm tra lại cấu hình Firebase.");
    });

    return () => unsubscribe();
  }, [user]);

  const showToast = (message) => {
    setToastMessage(message);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const copyToClipboard = (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => {
        showToast("Đã sao chép!");
      }).catch(err => showToast("Lỗi sao chép!"));
    } else {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand('copy');
        showToast("Đã sao chép!");
      } catch (err) {
        showToast("Lỗi sao chép!");
      }
      document.body.removeChild(textArea);
    }
  };

  const handleGoogleLogin = async () => {
    setAuthError('');
    const provider = new GoogleAuthProvider();
    try {
      await signInWithPopup(auth, provider);
    } catch (error) {
      if (error.code === 'auth/unauthorized-domain') {
        setAuthError("Tên miền này chưa được cấp phép. Vui lòng thêm tên miền hiện tại vào mục Authorized domains trong Firebase Console.");
      } else {
        setAuthError("Lỗi đăng nhập: " + error.message);
      }
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      setMasterKey(null);
      setVaultSalt(null);
      setVault([]);
      setEncryptedCloudData(null);
      setMasterPasswordInput('');
      setAppState('LOGIN');
      showToast("Đã đăng xuất");
    } catch (error) {
      showToast("Lỗi đăng xuất!");
    }
  };

  const handleLock = () => {
    setMasterKey(null);
    setVaultSalt(null);
    setVault([]);
    setAppState('UNLOCK');
    setMasterPasswordInput('');
    showToast("Đã khóa kho an toàn.");
  };

  // --- CHỨC NĂNG SAO LƯU & PHỤC HỒI ---
  const exportBackup = () => {
    if (!encryptedCloudData) {
      showToast("Không có dữ liệu để sao lưu!");
      return;
    }
    const dataStr = JSON.stringify(encryptedCloudData);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = `SecureVault_Backup_${new Date().toISOString().split('T')[0]}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
    showToast("Đã tải xuống file sao lưu an toàn!");
  };

  const handleImportBackup = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const content = e.target.result;
        const parsedData = JSON.parse(content);

        if (!parsedData.salt || !parsedData.iv || !parsedData.data) {
          throw new Error("File không hợp lệ");
        }

        if (!window.confirm("CẢNH BÁO: Phục hồi sẽ GHI ĐÈ toàn bộ mật khẩu hiện tại trên đám mây bằng dữ liệu từ file này. Bạn có chắc chắn?")) {
          event.target.value = null;
          return;
        }

        setIsSyncing(true);
        const docRef = getVaultDocRef(user.uid);
        await setDoc(docRef, parsedData);
        
        showToast("Phục hồi thành công! Vui lòng mở khóa lại.");
        handleLock(); // Bắt buộc người dùng nhập lại mật khẩu chính của bản backup để giải mã
      } catch (err) {
        showToast("Lỗi: File sao lưu không hợp lệ hoặc bị hỏng.");
      } finally {
        setIsSyncing(false);
        event.target.value = null; 
      }
    };
    reader.readAsText(file);
  };

  const saveVaultToCloud = async (newVault, currentKey, currentSalt) => {
    if (!user) return;
    setIsSyncing(true);
    try {
      const activeKey = currentKey || masterKey;
      const activeSalt = currentSalt || vaultSalt;

      const { ciphertext, iv } = await encryptData(newVault, activeKey);

      const storeData = {
        salt: buf2b64(activeSalt),
        iv: buf2b64(iv),
        data: buf2b64(ciphertext),
        updatedAt: new Date().toISOString()
      };

      const docRef = getVaultDocRef(user.uid);
      await setDoc(docRef, storeData);

      setVault(newVault);
    } catch (err) {
      showToast("Lỗi đồng bộ!");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSetup = async (e) => {
    e.preventDefault();
    if (masterPasswordInput !== confirmPasswordInput) {
      setAuthError("Mật khẩu xác nhận không khớp!");
      return;
    }
    if (masterPasswordInput.length < 8) {
      setAuthError("Mật khẩu phải có ít nhất 8 ký tự!");
      return;
    }

    try {
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const pwdKey = await getPasswordKey(masterPasswordInput);
      const key = await deriveKey(pwdKey, salt);
      
      setVaultSalt(salt);
      setMasterKey(key);
      
      const initialVault = [];
      await saveVaultToCloud(initialVault, key, salt);
      
      setAppState('READY');
      setMasterPasswordInput('');
      setConfirmPasswordInput('');
      setAuthError('');
      showToast("Khởi tạo thành công!");
    } catch (err) {
      setAuthError("Lỗi thiết lập mã hóa.");
    }
  };

  const handleUnlock = async (e) => {
    e.preventDefault();
    setAuthError('');
    try {
      await processUnlock(masterPasswordInput);
    } catch (err) {
      setAuthError("Sai mật khẩu chính!");
    }
  };

  const handleSaveItem = async (item) => {
    let newVault;
    if (editingItem) {
      newVault = vault.map(v => v.id === item.id ? item : v);
    } else {
      newVault = [...vault, { ...item, id: crypto.randomUUID() }];
    }
    await saveVaultToCloud(newVault);
    setShowAddModal(false);
    setEditingItem(null);
    showToast("Đã lưu & đồng bộ!");
  };

  const handleDeleteItem = async (id) => {
    const newVault = vault.filter(v => v.id !== id);
    await saveVaultToCloud(newVault);
    showToast("Đã xóa!");
  };

  const filteredVault = vault.filter(item => 
    item.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
    item.username.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // --- RENDER SCREENS ---

  if (appState === 'CHECKING_AUTH' || appState === 'CHECKING_DATA') {
    return (
      <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center p-4 font-sans text-slate-100">
        <Loader2 className="w-12 h-12 text-blue-500 animate-spin mb-4" />
        <p className="text-slate-400 font-medium">Đang tải dữ liệu an toàn...</p>
      </div>
    );
  }

  if (appState === 'LOGIN') {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4 font-sans text-slate-100">
        <div className="bg-slate-800 p-8 rounded-2xl shadow-2xl max-w-md w-full border border-slate-700 text-center">
          <div className="flex justify-center mb-6">
            <div className="bg-blue-500/20 p-4 rounded-full">
              <Shield className="w-12 h-12 text-blue-400" />
            </div>
          </div>
          <h1 className="text-2xl font-bold mb-2">SecureVault</h1>
          <p className="text-slate-400 mb-8 text-sm">
            Quản lý mật khẩu an toàn. Đồng bộ đám mây với chuẩn mã hóa quân đội.
          </p>

          {authError && (
            <div className="bg-red-500/10 border border-red-500/50 p-3 rounded-lg mb-6 flex items-start text-left">
              <AlertTriangle className="w-5 h-5 text-red-500 mt-0.5 mr-3 flex-shrink-0" />
              <p className="text-red-400 text-sm">{authError}</p>
            </div>
          )}

          <button 
            onClick={handleGoogleLogin}
            className="w-full bg-white text-slate-900 hover:bg-slate-100 font-bold py-3 px-4 rounded-lg transition-colors flex items-center justify-center shadow-lg"
          >
            <img src="https://www.svgrepo.com/show/475656/google-color.svg" className="w-6 h-6 mr-3" alt="Google" />
            Đăng nhập với Google
          </button>
        </div>
      </div>
    );
  }

  if (appState === 'SETUP') {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4 font-sans text-slate-100">
        <div className="bg-slate-800 p-8 rounded-2xl shadow-2xl max-w-md w-full border border-slate-700">
          <div className="flex items-center justify-between mb-6">
            <div className="bg-blue-500/20 p-3 rounded-full inline-block">
              <Shield className="w-8 h-8 text-blue-400" />
            </div>
            <div className="flex items-center space-x-2 text-sm text-slate-400 bg-slate-900 py-1 px-3 rounded-full border border-slate-700">
              <User className="w-4 h-4 text-blue-400" /> 
              <span className="truncate max-w-[120px]">{user?.email}</span>
            </div>
          </div>
          
          <h1 className="text-xl font-bold mb-2">Tạo Mật Khẩu Chính</h1>
          <p className="text-slate-400 mb-6 text-sm">
            Hãy tạo <strong>Mật khẩu chính</strong> để mã hóa kho lưu trữ.
          </p>
          
          <div className="bg-amber-900/30 border border-amber-700/50 p-4 rounded-lg mb-6 flex items-start">
            <AlertTriangle className="w-5 h-5 text-amber-500 mt-0.5 mr-3 flex-shrink-0" />
            <p className="text-amber-200 text-xs">
              <strong>Quan trọng:</strong> Tuyệt đối không được quên mật khẩu này. Hệ thống không thể khôi phục nó giúp bạn.
            </p>
          </div>

          <form onSubmit={handleSetup} className="space-y-4">
            <input 
              type="password" 
              value={masterPasswordInput}
              onChange={(e) => setMasterPasswordInput(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-blue-500"
              placeholder="Mật khẩu chính (ít nhất 8 ký tự)"
              required
            />
            <input 
              type="password" 
              value={confirmPasswordInput}
              onChange={(e) => setConfirmPasswordInput(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-blue-500"
              placeholder="Nhập lại mật khẩu"
              required
            />
            
            {authError && <p className="text-red-400 text-sm text-center">{authError}</p>}
            
            <button 
              type="submit" 
              disabled={isSyncing}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3 px-4 rounded-lg flex items-center justify-center"
            >
              {isSyncing ? <Loader2 className="w-5 h-5 animate-spin mr-2" /> : <Lock className="w-5 h-5 mr-2" />}
              Bắt đầu mã hóa
            </button>
            <button 
              type="button"
              onClick={handleLogout}
              className="w-full bg-transparent text-slate-400 hover:text-white py-2 text-sm mt-2"
            >
              Đăng xuất
            </button>
          </form>
        </div>
      </div>
    );
  }

  if (appState === 'UNLOCK') {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4 font-sans text-slate-100">
        <div className="bg-slate-800 p-8 rounded-2xl shadow-2xl max-w-md w-full border border-slate-700">
          <div className="flex items-center justify-between mb-6">
            <div className="bg-emerald-500/20 p-3 rounded-full inline-block">
              <Lock className="w-8 h-8 text-emerald-400" />
            </div>
            <div className="flex items-center space-x-2 text-sm text-slate-400 bg-slate-900 py-1 px-3 rounded-full border border-slate-700">
              <Cloud className="w-4 h-4 text-emerald-400" /> 
              <span className="truncate max-w-[100px]">{user?.email}</span>
            </div>
          </div>
          <h1 className="text-xl font-bold mb-2">Mở khóa Kho bảo mật</h1>
          <p className="text-slate-400 mb-8 text-sm">
            Nhập mật khẩu chính để giải mã dữ liệu của bạn.
          </p>

          <form onSubmit={handleUnlock} className="space-y-6">
            <input 
              type="password" 
              value={masterPasswordInput}
              onChange={(e) => setMasterPasswordInput(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-emerald-500"
              placeholder="Mật khẩu chính"
              required autoFocus
            />
            
            {authError && <p className="text-red-400 text-sm text-center">{authError}</p>}
            
            <div className="space-y-3">
              <button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-3 px-4 rounded-lg flex items-center justify-center">
                <Unlock className="w-4 h-4 mr-2" /> Giải mã
              </button>
              
              {isBiometricSupported && hasBiometricSaved && (
                <button type="button" onClick={handleBiometricUnlock} className="w-full bg-slate-800 hover:bg-slate-700 text-emerald-400 font-medium py-3 px-4 rounded-lg flex items-center justify-center border border-emerald-500/30">
                  <Fingerprint className="w-5 h-5 mr-2" /> Mở khóa bằng Sinh trắc học
                </button>
              )}
              
              <button type="button" onClick={handleLogout} className="w-full bg-slate-700 hover:bg-slate-600 text-white font-medium py-3 px-4 rounded-lg flex items-center justify-center">
                <LogOut className="w-4 h-4 mr-2" /> Đăng xuất
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 font-sans text-slate-200 flex flex-col">
      {/* Navbar - Tối ưu cho Mobile */}
      <nav className="bg-slate-800 border-b border-slate-700 sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <Shield className="w-7 h-7 text-blue-500" />
              <span className="font-bold text-lg text-white hidden sm:block">SecureVault</span>
            </div>
            
            <div className="flex items-center space-x-2">
              {isSyncing && <RefreshCw className="w-4 h-4 text-blue-400 animate-spin mr-2" />}
              
              {/* Desktop Search */}
              <div className="relative hidden md:block mr-2">
                <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
                <input 
                  type="text" 
                  placeholder="Tìm kiếm..." 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-slate-900 border border-slate-600 rounded-full pl-9 pr-4 py-1.5 text-sm focus:outline-none focus:border-blue-500 w-48 lg:w-64"
                />
              </div>

              {isBiometricSupported && !hasBiometricSaved && (
                <button onClick={enableBiometric} title="Bật Face ID / Vân tay" className="hidden md:flex p-2 text-emerald-400 hover:bg-slate-700 rounded-lg items-center text-sm font-medium border border-emerald-500/30 mr-1">
                  <Fingerprint className="w-5 h-5" />
                </button>
              )}

              {/* Nút Sao lưu & Phục hồi trên Desktop */}
              <button onClick={exportBackup} title="Tải file Sao lưu" className="p-2 text-blue-400 hover:bg-slate-700 rounded-lg hidden sm:block">
                <Download className="w-5 h-5" />
              </button>
              <button onClick={() => document.getElementById('backup-upload').click()} title="Phục hồi từ file" className="p-2 text-amber-400 hover:bg-slate-700 rounded-lg hidden sm:block">
                <Upload className="w-5 h-5" />
              </button>
              <input type="file" id="backup-upload" accept=".json" style={{ display: 'none' }} onChange={handleImportBackup} />

              <button onClick={handleLock} className="p-2 text-slate-300 hover:bg-slate-700 rounded-lg">
                <Lock className="w-5 h-5" />
              </button>
              <button onClick={handleLogout} className="p-2 text-red-400 hover:bg-red-900/30 rounded-lg">
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 max-w-6xl mx-auto px-4 py-6 w-full mb-20 md:mb-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl md:text-2xl font-bold text-white">Mật khẩu của bạn</h2>
          
          <div className="flex space-x-2">
            {/* Nút Sao lưu & Phục hồi cho Mobile */}
            <button onClick={exportBackup} title="Sao lưu" className="md:hidden flex bg-slate-800 text-blue-400 border border-blue-500/30 px-3 py-2 rounded-lg font-medium items-center">
              <Download className="w-5 h-5" />
            </button>
            <button onClick={() => document.getElementById('backup-upload').click()} title="Phục hồi" className="md:hidden flex bg-slate-800 text-amber-400 border border-amber-500/30 px-3 py-2 rounded-lg font-medium items-center">
              <Upload className="w-5 h-5" />
            </button>

            {isBiometricSupported && !hasBiometricSaved && (
              <button onClick={enableBiometric} title="Bật Sinh trắc học" className="md:hidden flex bg-slate-800 text-emerald-400 border border-emerald-500/30 px-3 py-2 rounded-lg font-medium items-center">
                <Fingerprint className="w-5 h-5" />
              </button>
            )}
            <button 
              onClick={() => { setEditingItem(null); setShowAddModal(true); }}
              className="hidden md:flex bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg font-medium items-center shadow-lg shadow-blue-600/20"
            >
              <Plus className="w-5 h-5 mr-1" /> Thêm mới
            </button>
          </div>
        </div>

        {/* Mobile Search */}
        <div className="relative md:hidden mb-6">
          <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
          <input 
            type="text" 
            placeholder="Tìm kiếm tài khoản..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-xl pl-10 pr-4 py-3 w-full focus:outline-none focus:border-blue-500 text-slate-200"
          />
        </div>

        {filteredVault.length === 0 ? (
          <div className="text-center py-20 bg-slate-800/30 rounded-2xl border border-slate-700/50 border-dashed mt-4">
            <Key className="w-12 h-12 mx-auto text-slate-600 mb-4" />
            <h3 className="text-lg font-medium text-slate-300 mb-1">Trống</h3>
            <p className="text-slate-500 text-sm">Chưa có dữ liệu nào được lưu.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredVault.map(item => (
              <PasswordCard 
                key={item.id} 
                item={item} 
                onEdit={() => { setEditingItem(item); setShowAddModal(true); }}
                onDelete={() => handleDeleteItem(item.id)}
                onCopy={copyToClipboard}
              />
            ))}
          </div>
        )}
      </main>

      {/* Nút Floating Action Button cho Mobile */}
      <button 
        onClick={() => { setEditingItem(null); setShowAddModal(true); }}
        className="md:hidden fixed bottom-6 right-6 w-14 h-14 bg-blue-600 text-white rounded-full flex items-center justify-center shadow-[0_4px_20px_rgba(37,99,235,0.5)] z-20"
      >
        <Plus className="w-6 h-6" />
      </button>

      {/* Modals & Toasts */}
      {showAddModal && (
        <PasswordFormModal 
          item={editingItem}
          onClose={() => setShowAddModal(false)}
          onSave={handleSaveItem}
          onCopy={copyToClipboard}
        />
      )}

      {toastMessage && (
        <div className="fixed bottom-6 left-1/2 transform -translate-x-1/2 md:left-auto md:right-6 md:translate-x-0 bg-slate-800 text-white px-5 py-3 rounded-full shadow-2xl border border-slate-700 flex items-center z-50 whitespace-nowrap">
          <Check className="w-4 h-4 text-emerald-400 mr-2" />
          <span className="text-sm">{toastMessage}</span>
        </div>
      )}
    </div>
  );
}

// --- THÀNH PHẦN HIỂN THỊ ITEM MẬT KHẨU ---
function PasswordCard({ item, onEdit, onDelete, onCopy }) {
  const [showPassword, setShowPassword] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const initial = item.title ? item.title.charAt(0).toUpperCase() : '?';

  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 p-4 hover:border-slate-500 transition-colors flex flex-col">
      <div className="flex justify-between items-start mb-4">
        <div className="flex items-center space-x-3 overflow-hidden">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center text-white font-bold text-lg flex-shrink-0">
            {initial}
          </div>
          <div className="truncate">
            <h3 className="font-semibold text-slate-100 truncate text-base">{item.title}</h3>
            <p className="text-xs text-slate-400 truncate">{item.username}</p>
          </div>
        </div>
        <div className="flex space-x-1 ml-2">
          <button onClick={onEdit} className="p-2 text-slate-400 hover:text-blue-400 bg-slate-900/50 rounded-lg">
            Sửa
          </button>
          {!confirmDelete ? (
            <button onClick={() => setConfirmDelete(true)} className="p-2 text-slate-400 hover:text-red-400 bg-slate-900/50 rounded-lg">
              <Trash2 className="w-4 h-4" />
            </button>
          ) : (
            <div className="flex space-x-1">
              <button onClick={onDelete} className="px-2 py-1 text-white bg-red-600 rounded-lg text-xs font-bold">XÓA</button>
              <button onClick={() => setConfirmDelete(false)} className="px-2 py-1 text-slate-300 bg-slate-600 rounded-lg text-xs">Hủy</button>
            </div>
          )}
        </div>
      </div>
      
      <div className="mt-auto space-y-2 bg-slate-900/50 p-3 rounded-lg border border-slate-700/50">
        <div className="flex justify-between items-center">
          <div className="text-sm text-slate-400 truncate flex-grow">
            MK: <span className="text-slate-200 font-mono tracking-wider ml-1">{showPassword ? item.password : '••••••••'}</span>
          </div>
          <div className="flex space-x-3 ml-2">
            <button onClick={() => setShowPassword(!showPassword)} className="text-slate-500 hover:text-white">
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
            <button onClick={() => onCopy(item.password)} className="text-slate-500 hover:text-blue-400">
              <Copy className="w-4 h-4" />
            </button>
          </div>
        </div>
        
        <div className="flex justify-between items-center">
          <div className="text-sm text-slate-400 truncate flex-grow">
            TK: <span className="text-slate-200 ml-1">{item.username}</span>
          </div>
          <button onClick={() => onCopy(item.username)} className="text-slate-500 hover:text-blue-400 ml-2">
            <Copy className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

// --- FORM THÊM / SỬA MẬT KHẨU (MODAL) ---
function PasswordFormModal({ item, onClose, onSave, onCopy }) {
  const [formData, setFormData] = useState({
    title: item?.title || '',
    username: item?.username || '',
    password: item?.password || '',
    url: item?.url || '',
    notes: item?.notes || ''
  });
  
  const [showGenerator, setShowGenerator] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    onSave({ ...item, ...formData });
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-end sm:items-center justify-center sm:p-4 z-50">
      <div className="bg-slate-800 sm:rounded-2xl rounded-t-2xl border border-slate-700 w-full max-w-lg shadow-2xl flex flex-col max-h-[90vh] animate-slide-up sm:animate-none">
        <div className="px-5 py-4 border-b border-slate-700 flex justify-between items-center bg-slate-800 sticky top-0 sm:rounded-t-2xl rounded-t-2xl">
          <h2 className="text-lg font-bold text-white">
            {item ? 'Sửa Mật khẩu' : 'Thêm Mới'}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-full bg-slate-700/50">
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <div className="p-5 overflow-y-auto">
          {showGenerator ? (
            <div className="mb-5 p-4 bg-slate-900 rounded-xl border border-blue-500/30">
              <h3 className="text-sm font-semibold text-blue-400 mb-3 flex items-center">
                <Shield className="w-4 h-4 mr-2" /> Tạo Mật khẩu an toàn
              </h3>
              <PasswordGenerator onApply={(pwd) => {setFormData({...formData, password: pwd}); setShowGenerator(false);}} onCancel={() => setShowGenerator(false)} />
            </div>
          ) : null}

          <form id="pwd-form" onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1 uppercase tracking-wider">Tên trang web hoặc App *</label>
              <input type="text" required value={formData.title} onChange={e => setFormData({...formData, title: e.target.value})} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-white focus:outline-none focus:border-blue-500" placeholder="VD: Google, Facebook..." />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1 uppercase tracking-wider">Tài khoản *</label>
              <input type="text" required value={formData.username} onChange={e => setFormData({...formData, username: e.target.value})} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-white focus:outline-none focus:border-blue-500" />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1 uppercase tracking-wider">Mật khẩu *</label>
              <div className="flex space-x-2">
                <input type="text" required value={formData.password} onChange={e => setFormData({...formData, password: e.target.value})} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-white focus:outline-none focus:border-blue-500 font-mono text-lg" />
                <button type="button" onClick={() => setShowGenerator(!showGenerator)} className="px-3 bg-slate-700 text-slate-200 rounded-lg flex items-center justify-center">
                  <RefreshCw className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1 uppercase tracking-wider">URL (Tuỳ chọn)</label>
              <input type="text" value={formData.url} onChange={e => setFormData({...formData, url: e.target.value})} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500" placeholder="https://example.com" />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1 uppercase tracking-wider">Ghi chú</label>
              <textarea rows="2" value={formData.notes} onChange={e => setFormData({...formData, notes: e.target.value})} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500 resize-none"></textarea>
            </div>
          </form>
        </div>
        
        <div className="px-5 py-4 border-t border-slate-700 bg-slate-800 flex justify-end space-x-3 pb-safe">
          <button onClick={onClose} className="px-5 py-2.5 text-slate-300 bg-slate-700 rounded-lg text-sm font-medium">Hủy</button>
          <button form="pwd-form" type="submit" className="px-5 py-2.5 bg-blue-600 text-white rounded-lg flex items-center text-sm font-medium">
            <Save className="w-4 h-4 mr-2" /> Lưu Lại
          </button>
        </div>
      </div>
    </div>
  );
}

// --- TRÌNH TẠO MẬT KHẨU TỰ ĐỘNG ---
function PasswordGenerator({ onApply, onCancel }) {
  const [length, setLength] = useState(16);
  const [useUpper, setUseUpper] = useState(true);
  const [useLower, setUseLower] = useState(true);
  const [useNumbers, setUseNumbers] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [generated, setGenerated] = useState('');

  const generatePassword = () => {
    let charset = '';
    if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (useNumbers) charset += '0123456789';
    if (useSymbols) charset += '!@#$%^&*()_+~`|}{[]:;?><,./-=';
    if (charset === '') return setGenerated('');

    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);
    let result = '';
    for (let i = 0; i < length; i++) result += charset[array[i] % charset.length];
    setGenerated(result);
  };

  useEffect(() => { generatePassword(); }, [length, useUpper, useLower, useNumbers, useSymbols]);

  return (
    <div className="space-y-4">
      <div className="flex items-center space-x-2">
        <div className="flex-grow bg-slate-950 p-3 rounded-lg border border-slate-700 text-center font-mono text-lg text-emerald-400 break-all flex items-center justify-center">
          {generated || "Lỗi"}
        </div>
        <button onClick={generatePassword} className="p-3 bg-slate-700 text-white rounded-lg">
          <RefreshCw className="w-5 h-5" />
        </button>
      </div>
      <div>
        <div className="flex justify-between text-sm text-slate-300 mb-1">
          <span>Độ dài:</span><span className="font-bold text-white">{length}</span>
        </div>
        <input type="range" min="8" max="64" value={length} onChange={(e) => setLength(parseInt(e.target.value))} className="w-full accent-blue-500" />
      </div>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <label className="flex items-center space-x-2"><input type="checkbox" checked={useUpper} onChange={(e) => setUseUpper(e.target.checked)} className="rounded" /><span className="text-slate-300">A-Z</span></label>
        <label className="flex items-center space-x-2"><input type="checkbox" checked={useLower} onChange={(e) => setUseLower(e.target.checked)} className="rounded" /><span className="text-slate-300">a-z</span></label>
        <label className="flex items-center space-x-2"><input type="checkbox" checked={useNumbers} onChange={(e) => setUseNumbers(e.target.checked)} className="rounded" /><span className="text-slate-300">0-9</span></label>
        <label className="flex items-center space-x-2"><input type="checkbox" checked={useSymbols} onChange={(e) => setUseSymbols(e.target.checked)} className="rounded" /><span className="text-slate-300">!@#$</span></label>
      </div>
      <div className="flex space-x-2 pt-2">
        <button onClick={onCancel} className="flex-1 py-2.5 bg-slate-800 text-slate-300 rounded-lg text-sm border border-slate-700">Đóng</button>
        <button disabled={!generated} onClick={() => onApply(generated)} className="flex-1 py-2.5 bg-emerald-600 text-white rounded-lg text-sm font-medium">Dùng mã này</button>
      </div>
    </div>
  );
}