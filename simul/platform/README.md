# Deployment
	Configure(*Config)
	Build() (error)
	Deploy() (error)
	Start() (error)
	Stop() (error)

The Life of a simulation:

1. Configure
    * read configuration
    * compile eventual files
2. Build
    * builds all files
    * eventually for different platforms
3. Cleanup
    * send killall to applications
4. Deploy
    * make sure the environment is up and running
    * copy files
5. Start
    * start all logservers
    * start all nodes
    * start all clients
6. Wait
    * wait for the applications to finish
    
