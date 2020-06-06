Class {
	#name : #VirusTotalService,
	#superclass : #Object,
	#instVars : [
		'apiKey',
		'client'
	],
	#classVars : [
		'Default'
	],
	#category : #VirusTotal
}

{ #category : #'instance creation' }
VirusTotalService class >> apiKey: apiKey [
	^ self new
		apiKey: apiKey;
		yourself
]

{ #category : #'instance creation' }
VirusTotalService class >> default [
	^ Default ifNil: [ Default := self apiKey: self publicApiKey ]
]

{ #category : #constants }
VirusTotalService class >> publicApiKey [
	"Note - this key is limited to 4 requests/min globally."

	"We may need to obtain a 4 requests/min/IP address key here: https://support.virustotal.com/hc/en-us/articles/115002091329-I-integrated-the-public-API-in-free-software-the-default-request-rate-is-too-low-to-attend-all-my-users"

	^ 'ac91073c8ce6038b9c44b5cc1a6f7d9c56b3e926bacf61efc684b771b793a2ac'
]

{ #category : #initialization }
VirusTotalService class >> reset [
	Default := nil
]

{ #category : #accessing }
VirusTotalService >> apiKey [
	^ apiKey
]

{ #category : #accessing }
VirusTotalService >> apiKey: anObject [
	apiKey := anObject
]

{ #category : #operations }
VirusTotalService >> basicResourcesString: resources [
	^ String
		streamContents: [ :stream | 
			resources asCollection sorted
				do: [ :each | stream nextPutAll: each asString trimBoth ]
				separatedBy: [ stream nextPut: $, ] ]
]

{ #category : #private }
VirusTotalService >> basicRetrieveReport: resource allInfo: aBoolean [
	| response entity |
	self trace: 'VirusTotal get report: ' , resource printString.
	response := self client
		url: 'https://www.virustotal.com/vtapi/v2/file/report';
		formAt: 'apikey' put: self apiKey;
		formAt: 'resource' put: resource;
		formAt: 'allinfo'
			put:
			(aBoolean
				ifTrue: [ '1' ]
				ifFalse: [ '0' ]);
		post;
		response.
	response isNoContent
		ifTrue: [ self error: 'Empty Response - quota reached?' ].
	entity := response entity.
	^ (self jsonReaderOn: entity contents readStream) next
]

{ #category : #accessing }
VirusTotalService >> client [
	^ client
		ifNil: [ client := ZnClient new
				timeout: 10;
				yourself ]
]

{ #category : #private }
VirusTotalService >> jsonReaderOn: aStream [
	^ (NeoJSONReader on: aStream)
		mapClass: NeoJSONObject;
		yourself
]

{ #category : #private }
VirusTotalService >> jsonWriterToOn: aStream [
	^ NeoJSONWriter on: aStream
]

{ #category : #operations }
VirusTotalService >> retrieveReports: resources [
	^ self retrieveReports: resources allInfo: false
]

{ #category : #operations }
VirusTotalService >> retrieveReports: resources allInfo: aBoolean [
	| result |
	result := self
		basicRetrieveReport: (self basicResourcesString: resources)
		allInfo: aBoolean.
	^ result isArray
		ifTrue: [ result ]
		ifFalse: [ Array with: result ]
]
