Class {
	#name : #VirusTotalServiceCache,
	#superclass : #Object,
	#instVars : [
		'service',
		'cache'
	],
	#classVars : [
		'Default'
	],
	#category : #VirusTotal
}

{ #category : #accessing }
VirusTotalServiceCache class >> default [
	^ Default ifNil: [ Default := self service: VirusTotalService default ]
]

{ #category : #initialization }
VirusTotalServiceCache class >> reset [
	Default := nil
]

{ #category : #accessing }
VirusTotalServiceCache class >> service: aVirusTotalService [
	^ self new
		setService: aVirusTotalService;
		yourself
]

{ #category : #initialization }
VirusTotalServiceCache >> initialize [
	super initialize.
	cache := TTLCache new
		maximumWeight: 10000;
		timeToLive: 1 day;
		yourself
]

{ #category : #initialization }
VirusTotalServiceCache >> reset [
	cache removeAll
]

{ #category : #operations }
VirusTotalServiceCache >> retrieveReports: resources [
	^ cache
		at: #retrieveReports: -> (service basicResourcesString: resources)
		ifAbsentPut: [ service retrieveReports: resources ]
]

{ #category : #operations }
VirusTotalServiceCache >> retrieveReports: resources allInfo: aBoolean [
	^ cache
		at:
			#retrieveReports:allInfo:
				-> ((service basicResourcesString: resources) , aBoolean asString)
		ifAbsentPut: [ service retrieveReports: resources allInfo: aBoolean ]
]

{ #category : #initializing }
VirusTotalServiceCache >> setService: aVirusTotalService [
	service := aVirusTotalService
]
