


### GIT HELPERS



newbranch:
# if NEWBRANCH is not defined, then abort with error
ifndef NEWBRANCH
	$(error NEWBRANCH is not set)
endif
	@echo "NEW branch selected is $(NEWBRANCH)"
	git submodule foreach git checkout -b $(NEWBRANCH)
	git checkout -b $(NEWBRANCH)
	git submodule foreach git push -u origin $(NEWBRANCH)
	git push -u origin $(NEWBRANCH)
