import numpy as np
import matplotlib.pyplot as plt
from sklearn.svm import SVC
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_selection import RFECV
from sklearn.datasets import make_classification
from sklearn.externals import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn import cluster


clean_name='cleandata.txt'
malicious_name='maliciousdata.txt'
#clean_test_name='cleandata.txt.test'
clean_test_name='cleandata'
#malicious_test_name='maliciousdata.txt.test'
malicious_test_name='testdata'


MONITOR = False
DEBUG_DATA = False
FEATURE_EXTRACTION = False

# Get data from txt files as numpy array
print "Getting training data from txt files."
clean_x = np.genfromtxt(clean_name, unpack=False, converters = {3: lambda s: float(s or 0)})
malicious_x = np.genfromtxt(malicious_name, unpack=False, converters = {3: lambda s: float(s or 0)})

malicious_y = np.ones((malicious_x.shape[0], 1))
clean_y = np.zeros((clean_x.shape[0], 1))

x = np.concatenate((clean_x, malicious_x),axis=0)
y = np.concatenate((clean_y, malicious_y),axis=0)

## Debug for data error 
if DEBUG_DATA:
    index = 0
    for i in x[:,0]:
        if np.isnan(i):
            print(index, i)
            index +=1
    
    
    index = 0
    for i in y[:,0]:
        if np.isnan(i):
            print(index, i)
            index +=1


##########
#### SEC1: The feature extraction
##########
print "Doing feature extraction:"
if FEATURE_EXTRACTION:
    print "Features are being evaluated:"
    svc = SVC(kernel="linear")
    rfecv = RFECV(estimator=svc, step=1, cv=StratifiedKFold(2), scoring='accuracy',  n_jobs=4, verbose=7)
    rfecv.fit(x, y.ravel())
else:
    rfecv = joblib.load('rfecv.pkl') 

## Draw feature number effects
if MONITOR:
    plt.figure()
    plt.xlabel("Number of features selected")
    plt.ylabel("Feature scores based on cross validation")
    plt.plot(range(1, len(grid.grid_scores_) + 1), grid.grid_scores_)
    plt.show()


x_ext=x[:,rfecv.support_]

##########
#### END OF SEC1
##########



##########
#### SEC2: Clustering for example reduction
##########
print "Doing clustering for example reduction:"
k = 16
kmeans = cluster.KMeans(n_clusters=k)
kmeans.fit(x_ext)

labels = kmeans.labels_
centroids = kmeans.cluster_centers_
x_set = []
y_set = []

for i in range(k):
    x_set.append(x_ext[np.where(labels==i)])
    y_set.append(y[np.where(labels==i)])
    plt.plot(x_set[-1][:,0],x_set[-1][:,1],'o')
    lines = plt.plot(centroids[i,0],centroids[i,1],'kx')
    plt.setp(lines,ms=15.0)
    plt.setp(lines,mew=2.0)

if MONITOR:
    plt.show()

rand_buf = np.random.choice(y_set[k-1].ravel(), y_set[i].shape, replace=False )
x_rand = x_set[k-1][(np.where(rand_buf==1)[0])]
y_rand = y_set[k-1][(np.where(rand_buf==1)[0])]
for i in range(k-1):
	rand_buf = np.random.choice(y_set[i].ravel(), y_set[i].shape, replace=False )
	x_buf = x_set[i][(np.where(rand_buf==1)[0])]
	y_buf = y_set[i][(np.where(rand_buf==1)[0])]
	x_rand = np.concatenate((x_rand, x_buf),axis=0)	
	y_rand = np.concatenate((y_rand, y_buf),axis=0)	

##########
#### END OF SEC2
##########





##########
#### SEC3: Construction of learner
##########
print "Train random forest classifier:"
clf = RandomForestClassifier(max_depth=2, random_state=0)
clf.fit(x_rand, y_rand.ravel())

##########
#### END OF SEC2
##########






##########
#### SEC TEST:
##########
print "Making tests:"
clean_x_test = np.genfromtxt(clean_test_name, unpack=False, converters = {3: lambda s: float(s or 0)})
malicious_x_test = np.genfromtxt(malicious_test_name, unpack=False, converters = {3: lambda s: float(s or 0)})

malicious_y_test = np.ones((malicious_x_test.shape[0], 1))
clean_y_test = np.zeros((clean_x_test.shape[0], 1))

x_test = np.concatenate((clean_x_test, malicious_x_test),axis=0)
x_test = x_test[:,rfecv.support_]
y_test = np.concatenate((clean_y_test, malicious_y_test),axis=0)

pr =  clf.predict(x_test)
print "Result: \t",  clf.predict(x_test)
print "Should be: \t",  y_test.ravel()

add = np.add(pr, y_test.ravel())

print "Total number of mismatches: ", np.where(add%2!=0)[0].shape[0]


test = np.genfromtxt('maliciousdata.txt.test.2', unpack=False, converters = {3: lambda s: float(s or 0)})
test = test[:,rfecv.support_]

print "\n"
print "Result: \t",  clf.predict(test)
print "Should be: \t",  [1,1]

##########
#### END OF SEC TEST
##########




