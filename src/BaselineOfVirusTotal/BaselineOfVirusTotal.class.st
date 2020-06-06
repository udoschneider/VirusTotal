Class {
	#name : #BaselineOfVirusTotal,
	#superclass : #BaselineOf,
	#category : #BaselineOfVirusTotal
}

{ #category : #baselines }
BaselineOfVirusTotal >> baseline: spec [
	<baseline>
	spec
		for: #common
		do: [ spec
				baseline: 'NeoJSON'
				with: [ spec repository: 'github://svenvc/NeoJSON/repository' ].
			spec package: #VirusTotal with: [ spec requires: #('NeoJSON') ] ]
]
