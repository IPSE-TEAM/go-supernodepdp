# SuperNode-PDP

### 同态加密

如果我们有一个加密函数 f , 把明文A变成密文A’, 把明文B变成密文B’，也就是说 f(A) = A’ ， f(B) = B’ 。另外我们还有一个解密函数 f−1f−1 能够将 f 加密后的密文解密成加密前的明文。

对于一般的加密函数，如果我们将A’和B’相加，得到C’。我们用f−1f−1 对C’进行解密得到的结果一般是毫无意义的乱码。

但是，如果 f 是个可以进行同态加密的加密函数， 我们对C’使用 f−1f−1 进行解密得到结果C， 这时候的C = A + B。这样，数据处理权与数据所有权可以分离，这样企业可以防止自身数据泄露的同时，利用云服务的算力。

### 加法同态和乘法同态


-  如果满足 f(A)+f(B)=f(A+B)f(A)+f(B)=f(A+B) ，我们将这种加密函数叫做加法同态。
-  如果满足 f(A)×f(B)=f(A×B)f(A)×f(B)=f(A×B) ，我们将这种加密函数叫做乘法同态。

如果一个加密函数同时满足加法同态和乘法同态，称为全同态加密，那么可以使用这个加密函数完成各种加密后的运算（加减运算、多项式求值、指数、对数、三角函数）。

### 同态加密算法

- RSA算法对于乘法操作是同态的。
- Paillier算法对加法是同态的。
- Gentry算法则是全同态的。

### 语义安全性（Semantic Security）

同态加密最基本安全性是语义安全性，直观来说，就是密文（Ciphertext）不泄露明文（Plaintext）中的任意信息。加密算法中还用到了一个很重要的量：随机数。也就是说，对于同样的明文m进行加密，得到的结果都不一样，即一个明文可以对应多个密文（many ciphertexts per plaintext）。

### 重要应用

用户将自己的数据加密后存储在一个不信任的远程服务器上，日后可以向远程服务器查询自己所需要的信息，存储与查询都使用密文数据，服务器将检索到的密文数据发回。用户可以解密得到自己所需的信息，而远程服务器却对存储和检索的信息一无所知。

### IPSE应用同态加密技术

**Setup** 任务下发节点提前下载任务得到数据D，切分成小块m1、m2,...，按照比例随机挑选数据块m作为明文，加入随机数生成c作为密文，然后将taskid、随机数、密文和随机挑选出的sub-hashlinks发送给SuperNode，存储节点接收到分发任务后，下载数据D，切分成小块并保存到本地，完成任务后提交到区块链上去。

**Challenge** SuperNode在区块链上数据记录里查询到taskid、hashlink和peerid，查找hashlink下的sub-hashlink，命中后，随机生成一个随机数r，加密得到密文，密文和保存的密文进行同态操作得到一个挑战chal，随机数r发送给存储节点发起挑战。

**Proof** 存储节点接收到挑战后，需要完成证明，需要从自己本地存储的数据中读取出明文m，然后和r一起执行相同的同态操作，在时间t范围内将证明结果result发送给SuperNode。

**Verify** SuperNode接收到证明结果后，需要验证在时间t范围内其result跟chal是否一致。


### 测试

	 go test -v -run="TestPDP" supernodepdp_test.go paillier.go 

- 第一步，DistributionNode生成钥匙对

  DistributionNode生成钥匙对，然后将私钥privKey发送给可信的SuperNode，将公钥publicKey广播出去。
  
- 第二步，DistributionNode初始化

  DistributionNode在分发任务之前，需要随机挑选一些任务进行下载，获得存储数据D，然后随机获取其中一小块数据data进行加密处理E(data,privKey)->ciphertext。将ciphertext发送给可信的SuperNode，委托SuperNode进行数据持有性挑战和检查。任务分发下去后，将taskid等数据上链，让SuperNode能随时发起挑战。
  
- 第三步，StorageMiner存储数据

  StorageMiner在链上获取到任务，下载完成任务，更新任务状态。
  
- 第四步，SuperNode发起挑战

  SuperNode监听链上已完成的任务状态，随机发起挑战，从链上获取随机因子，生成挑战chalciphertext,和taskid，sub-hashlink一起发送给StorageMiner，存储矿工需要在时间t内完成证明。
  
- 第五步，StorageMiner完成证明

  StorageMiner在接收到挑战后，需要立马完成证明，根据taskid，sub-hasklink快速查找到挑战的数据块storedData，Proof(storedData,chal)->proof。完成证明后立马回传proof给SuperNode。

- 第六步，SuperNode完成验证

  SuperNode接收到proof后，验证 Verify(privKey,chalciphertext,proof)->{"success","failure"}，如果验证通过，更改taskid的状态，给StorageMiner相应的奖励，如果失败，给StorageMiner相应的惩罚。
  
